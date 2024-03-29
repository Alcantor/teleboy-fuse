#!/usr/bin/python3

import requests, re, sys
from os import path
from fusepy import FUSE, FuseOSError, Operations, LoggingMixIn
import os
from collections import defaultdict
from errno import ENOENT, EPERM, EIO
from stat import S_IFDIR, S_IFLNK, S_IFREG
import time
import m3u8, hashlib
from datetime import datetime
import shutil

class Teleboy:
  def __init__(self):
    self.uagent = "Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:12.0) Gecko/20100101 Firefox/12.0"
    self.session = None
    self.userid = None
    self.apikey = None

  # LOGIN ----------------------------------------------------------------------
  # Login successfully or throw an exception
  def login(self, login, password):
    resp = requests.post(
      "https://www.teleboy.ch/login_check",
      data={
        'login': login,
        'password': password,
        'keep_login': "1"
      },
      headers={'User-Agent': self.uagent},
      allow_redirects=False)
    self.session = resp.cookies['cinergy_s']

    resp = requests.get(
      "https://www.teleboy.ch/live", 
      headers={'User-Agent': self.uagent},
      cookies=resp.cookies,
      allow_redirects=False)
    m = re.search("'?userId'?\s*:\s*([0-9]*),", resp.text)
    self.userid = m.group(1)
    m = re.search("'?tvapiKey'?\s*:\s*'([0-9a-f]*)',", resp.text)
    self.apikey = m.group(1)
    print("Login successfully")
    print("Session is "+self.session)
    print("User ID is "+self.userid)
    print("API Key is "+self.apikey)

  # Teleboy API ----------------------------------------------------------------
  # Get the JSON response or throw an exception
  def tapi_get(self, url):
    resp = requests.get(
      "https://tv.api.teleboy.ch"+url,
      headers={
        'User-Agent': self.uagent,
        'x-teleboy-apikey': self.apikey,
        'x-teleboy-session': self.session
      },
      allow_redirects=False)
    return resp.json()

  # Return an array of tuple with station id and label.
  def tapi_get_stations(self):
    #stations = self.tapi_get("/epg/broadcasts/now?expand=flags,station,logos,previewImage")
    stations = self.tapi_get("/epg/broadcasts/now?expand=station")
    for s in stations['data']['items']:
      yield (s['station_id'], s['station_label'])

  # Return an array of tuple with id, slug, begin, end, station_id
  def tapi_get_epg(self, station_id, begin, end):
    fmt = "%Y-%m-%dT%H:%M:%S%z"
    begin = datetime.fromtimestamp(begin).strftime(fmt)
    end = datetime.fromtimestamp(end).strftime(fmt)
    broadcasts = self.tapi_get("/epg/broadcasts?begin="+begin+"&end="+end+"&station="+str(station_id))
    for b in broadcasts['data']['items']:
      begin = datetime.strptime(b['begin'], fmt).timestamp()
      end = datetime.strptime(b['end'], fmt).timestamp()
      yield (b['id'], b['slug'], begin, end, b['station_id'])

  # Return the HLS Live Stream URL
  def tapi_get_live_hls(self, station_id):
    live = self.tapi_get("/users/"+self.userid+"/stream/live/"+str(station_id)+"?alternative=0")
    return live['data']['stream']['url']

  # M3U8 -----------------------------------------------------------------------
  # Get the M3U8 response or throw an exception
  def m3u8_get(self, url):
    resp = requests.get(
      url,
      headers={
        'User-Agent': self.uagent
      },
      allow_redirects=True)
    return m3u8.loads(resp.text)

  # Return the HLS Live Stream Variant URL
  def m3u8_get_live_variant(self, station_id, max_bandwidth):
    url_master = self.tapi_get_live_hls(station_id)
    master = self.m3u8_get(url_master)
    if(not master.is_variant):
      return master_url
    # Select the variant with the highest bitrate but under the max_bandwidth
    bandwidth = 0;
    url_variant = None;
    for p in master.playlists:
      if p.stream_info.bandwidth > max_bandwidth:
        continue
      if p.stream_info.bandwidth > bandwidth:
        bandwidth = p.stream_info.bandwidth
        url_variant = p.uri
    return url_variant;

  # Segments -------------------------------------------------------------------
  # Return the HLS Live Stream Segment Tuple (base_url, seg_id, seg_ext, seg_duration)
  def seg_get_live_last(self, station_id, max_bandwidth=5000000):
    url_variant = self.m3u8_get_live_variant(station_id, max_bandwidth)
    m3u8_obj = self.m3u8_get(url_variant)
    uri_split = m3u8_obj.segments[-1].uri.split(".")
    return (path.dirname(url_variant), int(uri_split[0]), uri_split[1], m3u8_obj.target_duration);

  # Return the Segment data
  def seg_download(self, base_url, seg_id, seg_ext):
    print("GET Segment:",seg_id)
    resp = requests.get(
      base_url+'/'+str(seg_id)+seg_ext,
      headers={
        'User-Agent': self.uagent
      },
      allow_redirects=True)
    return resp.content

  # Return the Segment size
  def seg_size(self, base_url, seg_id, seg_ext):
    print("HEAD Segment:",seg_id)
    resp = requests.head(
      base_url+'/'+str(seg_id)+seg_ext,
      headers={
        'User-Agent': self.uagent
      },
      allow_redirects=True)
    return int(resp.headers['Content-Length'])

  # Cached Segments ------------------------------------------------------------
  # Return the Segment data, using the cache if available
  def seg_download_cached(self, base_url, seg_id, seg_ext, cache_dir, offset, size):
    cache_path = os.path.join(cache_dir,str(seg_id)+'.'+seg_ext)
    if(os.path.exists(cache_path)):
      file = open(cache_path, 'rb')
      file.seek(offset)
      data = file.read(size)
      file.close()
    else:
      data = self.seg_download(base_url, seg_id, seg_ext)
      file = open(cache_path, 'wb')
      file.write(data)
      file.close()
      data = data[offset:offset+size]
    return data

  # Return the Segment size, using the cache if available
  def seg_size_cached(self, base_url, seg_id, seg_ext, cache_dir, cache_0size=False):
    cache_path = os.path.join(cache_dir,str(seg_id)+'.'+seg_ext)
    if(os.path.exists(cache_path)):
      size = os.stat(cache_path).st_size
    else:
      cache_path += ".size"
      if(os.path.exists(cache_path)):
        file = open(cache_path, 'r')
        size = int(file.readline())
        file.close()
      else:
        size = self.seg_size(base_url, seg_id, seg_ext)
        # Do not cache size of zero, because the segment could be created
        if size > 0 or cache_0size:
          file = open(cache_path, 'w')
          file.write(str(size))
          file.close()
    return size

  # Offset ---------------------------------------------------------------------
  def seg_offset2seg_cached(self, base_url, begin_seg_id, end_seg_id, seg_ext, cache_dir, offset):
    seg_id = begin_seg_id
    cache_0size = True
    while True:
      size = self.seg_size_cached(base_url, seg_id, seg_ext, cache_dir, cache_0size)
      # If first segments are zero size it's probably because we are beyond the
      # 6 hours replay limit. Those segments will never be available.
      # In couterpart the last segments could be available in the future.
      if size > 0:
        cache_0size = False
      # We've got the corresponding segment
      if offset < size:
        available_size = size - offset
        return seg_id, offset, available_size
      # We reach the last segment and the offset was not found
      if seg_id >= end_seg_id:
        return seg_id, size, 0
      # Next segment
      offset -= size
      seg_id += 1

class TeleboyFS(LoggingMixIn, Operations):
  def __init__(self, username, password, additionnal_time):
    self.stations = {}
    self.broadcasts = {}
    now = time.time()
    self.broadcasts_ls_min_interval = 60
    self.additionnal_time = additionnal_time
    self.root = {
      'st_mode': (S_IFDIR | 0o755),
      'st_ctime': now,
      'st_mtime': now,
      'st_atime': now,
      'st_uid': 0,
      'st_gid': 0,
      'st_size': 1024
    }
    self.t = Teleboy()
    self.t.login(username, password)
    self.populate_stations()

  # Fill the stations dictionary
  def populate_stations(self):
    i = 0
    now = time.time()
    for id,label in self.t.tapi_get_stations():
      i += 1
      station_path = "ID-{:03}".format(id)
      # Don't overwrite existing keys
      if station_path in self.stations: continue
      ino_dict = {
        'stat': {
          'st_mode': (S_IFDIR | 0o755),
          'st_ctime': now,
          'st_mtime': now,
          'st_atime': now,
          'st_uid': 0,
          'st_gid': 0,
          'st_size': 1024
        },
        'station_id': id,
        'ts_populated': now-self.broadcasts_ls_min_interval
      }
      self.stations[station_path] = ino_dict
      self.stations["{:03}-{}".format(i,label)] = ino_dict

  # Fill the broadcasts dictionary
  def populate_broadcasts(self, station_id):
    now = time.time()
    farback = now-(6*60*60)
    i = 0
    base_url, seg_id, seg_ext, seg_duration = self.t.seg_get_live_last(station_id)
    # Remove old entries
    first_available_seg_id = seg_id - int((now - farback)/seg_duration)
    for k in list(self.broadcasts): # Copy the keys into a list
      if self.broadcasts[k]['station_id'] == station_id:
        if self.broadcasts[k]['seg_info'][2] < first_available_seg_id:
          del self.broadcasts[k]
    # Add new entries
    for id,slug,begin,end,station_id in self.t.tapi_get_epg(station_id, farback, now):
      broadcast_path = "ID-{:08}.ts".format(id)
      # Don't overwrite existing keys
      if broadcast_path in self.broadcasts: continue
      begin = max(begin, farback)
      begin_seg_id = seg_id - int((now - begin)/seg_duration)
      end_seg_id = seg_id - int((now - end + self.additionnal_time)/seg_duration)
      cache = os.path.join("cache",str(station_id))
      if not os.path.exists(cache):
        os.makedirs(cache)
      ino_dict = {
        'stat': {
          'st_mode': (S_IFREG | 0o444),
          'st_ctime': now,
          'st_mtime': now,
          'st_atime': now,
          'st_uid': 0,
          'st_gid': 0,
          # Size approximation works great with mplayer but not with vlc and kodi.
          # Those last ones trie to read the end of the file, which causes a lot of HEAD requests.
          #'st_size': self.t.seg_size_cached(base_url, seg_id, seg_ext, cache)*(end_seg_id-begin_seg_id)
          'st_size': 10000
        },
        'id': id,
        'begin': begin,
        'end': end,
        'station_id': station_id,
        'cache': cache,
        'seg_info': (base_url, begin_seg_id, end_seg_id, seg_ext, seg_duration)
      }
      self.broadcasts[broadcast_path] = ino_dict
      self.broadcasts["{}-{}.ts".format(datetime.fromtimestamp(begin).strftime("%H%M"),slug)] = ino_dict

  # Fill the broadcasts dictionary max every 60 seconds
  def populate_broadcasts_cached(self, station_ino_dict):
    now = time.time()
    if(station_ino_dict['ts_populated'] + self.broadcasts_ls_min_interval < now):
      station_ino_dict['ts_populated'] = now
      self.populate_broadcasts(station_ino_dict['station_id'])

  # Return the stat dictionary from a given path
  def get_path2stat(self, path):
    if path == '/':
      return self.root
    path = path.split('/')
    if len(path) == 2 and path[1] in self.stations:
      return self.stations[path[1]]['stat']
    if len(path) == 3 and path[1] in self.stations:
      self.populate_broadcasts_cached(self.stations[path[1]])
      if path[2] in self.broadcasts:
        return self.broadcasts[path[2]]['stat']
    raise FuseOSError(ENOENT)

  def chmod(self, path, mode):
    stat = self.get_path2stat(path)
    stat['st_mode'] &= 0o770000
    stat['st_mode'] |= mode

  def chown(self, path, uid, gid):
    stat = self.get_path2stat(path)
    stat['st_uid'] = uid
    stat['st_gid'] = gid

  def create(self, path, mode):
    raise FuseOSError(EPERM)

  def getattr(self, path, fh=None):
    return self.get_path2stat(path)

  def mkdir(self, path, mode):
    raise FuseOSError(EPERM)

  def open(self, path, flags):
    path = path.split('/')
    if len(path) != 3 or path[1] not in self.stations:
      raise FuseOSError(ENOENT)
    self.populate_broadcasts_cached(self.stations[path[1]])
    if path[2] not in self.broadcasts:
      raise FuseOSError(ENOENT)

    # File handle is the EPG id
    return self.broadcasts[path[2]]['id']

  def read(self, path, size, offset, fh):
    path = path.split('/')
    if len(path) != 3 or path[1] not in self.stations or path[2] not in self.broadcasts:
      raise FuseOSError(ENOENT)
    b = self.broadcasts[path[2]]

    # Variables
    base_url, seg_begin_id, seg_end_id, seg_ext, seg_duration = b['seg_info']
    cache = b['cache']
    data = b""

    try:
      while True:
        seg_id, seg_offset, available_size = self.t.seg_offset2seg_cached(base_url, seg_begin_id, seg_end_id, seg_ext, cache, offset)
        if available_size == 0:
          break
        if size <= available_size:
          data += self.t.seg_download_cached(base_url, seg_id, seg_ext, cache, seg_offset, size)
          minfilesize = offset+available_size
          # Look 10 segments ahead to allow seeking forward
          #for i in range(seg_id, min(seg_id+10, seg_end_id)):
          #  minfilesize += self.t.seg_size_cached(base_url, i, seg_ext, cache, False)
          if(b['stat']['st_size'] < minfilesize):
            b['stat']['st_size'] = minfilesize
          break
        else:
          data += self.t.seg_download_cached(base_url, seg_id, seg_ext, cache, seg_offset, available_size)
          offset += available_size
          size -= available_size
    except e:
      print(e)
    #  raise FuseOSError(EIO)
    return data

  def readdir(self, path, fh):
    if(path == '/'): return ['.', '..'] + [k for k in self.stations]
    path = path.split('/')
    if len(path) != 2 or path[1] not in self.stations:
      raise FuseOSError(ENOENT)
    s = self.stations[path[1]]
    self.populate_broadcasts_cached(s)
    return ['.', '..'] + [k for k in self.broadcasts if self.broadcasts[k]['station_id'] == s['station_id']]

  def readlink(self, path):
    return self.data[path]

  def rename(self, old, new):
    raise FuseOSError(EPERM)

  def rmdir(self, path):
    raise FuseOSError(EPERM)

  def statfs(self, path):
    return dict(f_bsize=512, f_blocks=4096, f_bavail=2048)

  def symlink(self, target, source):
    raise FuseOSError(EPERM)

  def truncate(self, path, length, fh=None):
    pass

  def unlink(self, path):
    raise FuseOSError(EPERM)

  def utimens(self, path, times=None):
    now = time.time()
    atime, mtime = times if times else (now, now)
    stat = self.get_path2stat(path)
    stat['st_atime'] = atime
    stat['st_mtime'] = mtime

  def write(self, path, data, offset, fh):
    raise FuseOSError(EPERM)

if len(sys.argv) < 5:
  print(sys.argv[0],"login password mountpoint additionnal_time")
else:
  FUSE(TeleboyFS(sys.argv[1],sys.argv[2], int(sys.argv[4])), sys.argv[3], nothreads=True, foreground=True)

