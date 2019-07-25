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

class Teleboy:
  def __init__(self):
    self.uagent = "Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:12.0) Gecko/20100101 Firefox/12.0"
    self.session = None
    self.userid = None
    self.apikey = None

  # LOGIN ----------------------------------------------------------------------
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

  def tapi_get_channels(self):
    channels = self.tapi_get("/epg/broadcasts/now?expand=flags,station,logos,previewImage")
    for c in channels['data']['items']:
      yield (c['station_id'], c['station_label'])

  def tapi_get_epg(self, station_id, begin, end):
    fmt = "%Y-%m-%dT%H:%M:%S%z"
    begin = datetime.fromtimestamp(begin).strftime(fmt)
    end = datetime.fromtimestamp(end).strftime(fmt)
    broadcasts = self.tapi_get("/epg/broadcasts?begin="+begin+"&end="+end+"&station="+str(station_id))
    #broadcasts = self.tapi_get("/epg/broadcasts?begin="+begin+"&end="+end)
    for b in broadcasts['data']['items']:
      begin = datetime.strptime(b['begin'], fmt).timestamp()
      end = datetime.strptime(b['end'], fmt).timestamp()
      yield (b['id'], b['slug'], begin, end, b['station_id'])

  def tapi_get_live_hls(self, station_id):
    live = self.tapi_get("/users/"+self.userid+"/stream/live/"+str(station_id)+"?alternative=0")
    return live['data']['stream']['url']

  # M3U8 -----------------------------------------------------------------------
  def m3u8_get(self, url):
    resp = requests.get(
      url,
      headers={
        'User-Agent': self.uagent
      },
      allow_redirects=True)
    return m3u8.loads(resp.text)

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
  def seg_get_live_last(self, station_id, max_bandwidth=5000000):
    url_variant = self.m3u8_get_live_variant(station_id, max_bandwidth)
    m3u8_obj = self.m3u8_get(url_variant)
    uri_split = m3u8_obj.segments[-1].uri.split(".")
    return (path.dirname(url_variant), int(uri_split[0]), uri_split[1], m3u8_obj.target_duration);

  def seg_download(self, base_url, seg_id, seg_ext):
    print("GET Segment:",seg_id)
    resp = requests.get(
      base_url+'/'+str(seg_id)+seg_ext,
      headers={
        'User-Agent': self.uagent
      },
      allow_redirects=True)
    return resp.content

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

  def seg_offset2seg_cached(self, base_url, seg_id, seg_ext, cache_dir, offset):
    while True:
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
          if size > 0:
            file = open(cache_path, 'w')
            file.write(str(size))
            file.close()
      if size <= 0:
         raise Exception("Segment not available");
      if offset < size:
        available_size = size - offset;
        return seg_id, offset, available_size;
      else:
        seg_id += 1
        offset -= size

class TeleboyFS(LoggingMixIn, Operations):
  def __init__(self, username, password):
    self.channels = {}
    self.broadcasts = {}
    now = time.time()
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
    self.populate_channel()

  def populate_channel(self):
    now = time.time()
    for c in self.t.tapi_get_channels():
      self.channels[c[1]] = {
        'stat': {
          'st_mode': (S_IFDIR | 0o755),
          'st_ctime': now,
          'st_mtime': now,
          'st_atime': now,
          'st_uid': 0,
          'st_gid': 0,
          'st_size': 1024
        },
        'station_id': c[0],
        'is_populated': False
      }

  def populate_broadcast(self, station_id):
    now = time.time()
    base_url, seg_id, seg_ext, seg_time = self.t.seg_get_live_last(station_id)
    for b in self.t.tapi_get_epg(station_id, now-(6*60*60), now):
      begin_seg_id = seg_id - int((now - b[2])/seg_time)
      end_seg_id = seg_id - int((now - b[3])/seg_time)
      cache = os.path.join("cache",str(b[4]))
      if not os.path.exists(cache):
        os.makedirs(cache)
      self.broadcasts[b[1]+'.ts'] = {
        'stat': {
          'st_mode': (S_IFREG | 0o755),
          'st_ctime': now,
          'st_mtime': now,
          'st_atime': now,
          'st_uid': 0,
          'st_gid': 0,
          'st_size': 1000000000
        },
        'id': b[0],
        'begin': b[2],
        'end': b[3],
        'station_id': b[4],
        'cache': cache,
        'seg_info': (base_url, begin_seg_id, seg_ext, seg_time)
      }

  def get_path2stat(self, path):
    if  (path == '/'): return self.root
    path = path[1:]
    if path in self.channels:
      return self.channels[path]['stat']
    path = os.path.basename(path)
    if path in self.broadcasts:
      return self.broadcasts[path]['stat']
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
    slug = os.path.basename(path)
    if not slug in self.broadcasts:
      raise FuseOSError(ENOENT)
    b = self.broadcasts[slug]

    # File handle is the EPG id
    return b['id']

  def read(self, path, size, offset, fh):
    slug = os.path.basename(path)
    if not slug in self.broadcasts:
      raise FuseOSError(ENOENT)
    b = self.broadcasts[slug]

    base_url, seg_id, seg_ext, seg_time = b['seg_info']
    cache = b['cache']
    try:
      data = b""
      while True:
        seg_id, offset, available_size = self.t.seg_offset2seg_cached(base_url, seg_id, seg_ext, cache, offset)
        if size < available_size:
          data += self.t.seg_download_cached(base_url, seg_id, seg_ext, cache, offset, size)
          break
        else:
          data += self.t.seg_download_cached(base_url, seg_id, seg_ext, cache, offset, available_size)
          offset += available_size
          size -= available_size
    except:
      raise FuseOSError(EIO)
    #file = open("aha.ts", 'rb')
    #file.seek(offset)
    return data

  def readdir(self, path, fh):
    print("readdir", path, fh)
    if(path == '/'):
      return ['.', '..'] + [k for k in self.channels]
    else:
      station_label = path[1:]
      if station_label not in self.channels:
        raise FuseOSError(ENOENT)
      s = self.channels[station_label]
      station_id = s['station_id']
      if not s['is_populated']:
        self.populate_broadcast(station_id)
        s['is_populated'] = True
      return ['.', '..'] + [k for k in self.broadcasts if self.broadcasts[k]['station_id'] == station_id]

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
    print("Write")
    raise FuseOSError(EPERM)

#with requests.get(url_segment, headers=teleboy_api_headers, allow_redirects=False) as resp:
#	open('test.ts', 'wb').write(resp.content)
FUSE(TeleboyFS(sys.argv[1],sys.argv[2]), "/tmp/test", nothreads=True, foreground=True)

