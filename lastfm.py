#!/usr/bin/env python
# encoding: utf-8
from __future__ import print_function
"""
backup_lastfm
===============
Personal Last.fm Track data liberation backup utility

"""

import collections
import codecs
import csv
import cStringIO
import datetime
import os.path
import json
import logging
import sys
import time

import bs4
import requests

USERNAME="westurner"
PASSWORD="invalid"
USER_AGENT="""Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/32.0.1700.107 Chrome/32.0.1700.107 Safari/537.36"""

log = logging.getLogger()
log.setLevel(logging.DEBUG)

def setup_http_debugging():
    """
    Setup httplib and requests debugging
    """
    return None
    # these two lines enable debugging at httplib level (requests->urllib3->httplib)
    # you will see the REQUEST, including HEADERS and DATA, and RESPONSE with HEADERS but without DATA.
    # the only thing missing will be the response.body which is not logged.
    import httplib
    httplib.HTTPConnection.debuglevel = 1

    logging.basicConfig() # you need to initialize logging, otherwise you will not see anything from requests
    logging.getLogger().setLevel(logging.DEBUG)
    requests_log = logging.getLogger("requests.packages.urllib3")
    requests_log.setLevel(logging.DEBUG)
    requests_log.propagate = True


def build_requests_session():
    """
    Returns:
        requests.Session: a configured requests.Session object
    """
    s = requests.Session()
    s.headers.update({'User-agent': USER_AGENT})
    return s


def configure_session_cookies(s):
    cookiestr = raw_input("Paste cookie str: ")
    cookiedict = dict([x.lstrip().split('=',1) for x in cookiestr.split(';')])
    requests.cookies.cookiejar_from_dict(
        cookiedict,
        s.cookies,
        overwrite=True)
    return s


def login_lastfm(s, username=None, password=None, delay=6, from_session=None):
    """
    Log a mechanize instance into Last.fm

    Args:
        b (requests.Session): configured requests.Session instance
        username (str): Last.fm username
        password (str): Last.fm password
        delay (int): Seconds to delay between GET and POST to /login

    Returns:
        requests.Session: logged-in requests.Session

    """
    log.debug("Logging in as %r..." % username)
    LOGIN_URL = "https://secure.last.fm/login"
    s = build_requests_session()

    # TODO
    return configure_session_cookies(s)

    resp = s.get(LOGIN_URL, verify=True)
    post_data = (
        'refererKey=&backto=&'
        'username=%s&password=%s&login=Come+on+in') % (username, password)
    time.sleep(delay)
    resp = s.post(LOGIN_URL, data=post_data, verify=True)
    if resp.status_code != requests.codes.ok:
        raise Exception(resp)
    log.debug(s.cookies)
    bs = bs4.BeautifulSoup(resp.content)
    if bs.find('div', {'id':'loginForm'}):
        for l in unicode(bs).split('\n'):
            log.error(l)
        raise Exception("AuthenticationError:")

    time.sleep(delay)
    log.debug("Logged in as %r" % username)
    return s


Track = collections.namedtuple('Track',
    ('date',
     'artist',
     'track',
     'loved',
     'lastfm_artist_link',
     'lastfm_track_link'))

def extract_tracks(html):
    """
    Parse Track namedtuples from Last.fm compact HTML track listings

    Args:
        html (basestring): html to parse tracks from

    Returns:
        generator: generator of Track namedtuples
    """
    bs = bs4.BeautifulSoup(html)
    #tbl = bs.find('table', {'id':'deletablert'})
    tbl = bs.find('table', {'class':'candyStriped tracklist'})
    if tbl is None:
        log.debug('###')
        log.debug(bs.find('article'))
        log.debug('###')
        log.debug(bs.find_all('table'))
        raise Exception("ParseError: didn't find a track table")
    for row in tbl.find_all('tr'):
        subj = row.find('td', {'class':'subjectCell'})
        artist, track = subj.find_all('a')
        # todo: artist.text, artist['href'], track.text, track['href']
        loved = row.find('td', {'class':'lovedCell'})
        loved_img = bool(loved.find('img'))
        date = row.find('td', {'class':'dateCell last'})
        _dt = date.find('time')
        dt = _dt['datetime'] # isoformat?, datetime.txt
        yield Track(
            dt,
            artist.text,
            track.text,
            loved_img,
            u'http://last.fm' + artist['href'],
            u'http://last.fm' + track['href'],
        )


def extract_track_data(s, username, delay=5, max_pages=None):
    """
    Page through all Last.fm track pages and emit Track namedtuples

    Args:
        s (request.Session): requests.Session object
        delay (int): seconds to delay between requests

    Returns:
        generator: generator of Track tuples

    """
    URL = 'http://www.last.fm/user/%s/tracks?view=compact&page=%%d' % username
    url = URL % 1
    resp = s.get(url)
    bs = bs4.BeautifulSoup(resp.content)
    pagin = bs.find('div', {'class':'whittle-pagination'})
    links = pagin.find_all('a')
    max_link = links[1]  # [2] ... [n_max]
    n_max = int(max_link.text)
    log.debug("Found %d pages of Tracks" % n_max)
    if max_pages:
        n_max = min(n_max, max_pages)
    for n in xrange(1, n_max + 1):
        if n != 1:
            url = URL % n
            resp = s.get(url)
        log.debug("Extracting tracks from page # %d of %d" % (n, n_max))
        for track in extract_tracks(resp.content):
            yield track
        if delay:
            time.sleep(delay)


def write_track_data_to_json(data, destination, meta=None):
    """
    Serialize Track namedtuples to JSON

    Args:
        data (iterable): iterable of Track namedtuples
        destination (str or write-able): path or fileobj to write JSON into
        meta (dict): dict of additional metadata values to include (optional)

    """
    log.debug("Writing track data to %r" % destination)
    now = datetime.datetime.now()
    obj = collections.OrderedDict((
        ('date_retrieved', now.isoformat()),
        ('tracks', [x._asdict() for x in data]),
    ))
    if meta:
        meta.pop('date_retrieved', None)
        meta.pop('tracks', None)
        obj.update(meta)
    if hasattr(destination, 'write'):
        json.dump(obj, destination, indent=2)
    else:
        with codecs.open(destination, 'w', encoding='utf-8') as f:
            json.dump(obj, f, indent=2)

class UnicodeCSVWriter:
    """
    A CSV writer which will write rows to CSV file "f",
    which is encoded in the given encoding.

    from: http://docs.python.org/2/library/csv.html#csv-examples
    """

    def __init__(self, f, dialect=csv.excel, encoding="utf-8", **kwds):
        # Redirect output to a queue
        self.queue = cStringIO.StringIO()
        self.writer = csv.writer(self.queue, dialect=dialect, **kwds)
        self.stream = f
        self.encoder = codecs.getincrementalencoder(encoding)()

    def writerow(self, row):
        def _encode_row(row):
            for s in row:
                if isinstance(s, basestring):
                    yield s.encode("utf-8")
                else:
                    yield s
        self.writer.writerow(tuple(_encode_row(row)))
        # Fetch UTF-8 output from the queue ...
        data = self.queue.getvalue()
        data = data.decode("utf-8")
        # ... and reencode it into the target encoding
        data = self.encoder.encode(data)
        # write to the target stream
        self.stream.write(data)
        # empty queue
        self.queue.truncate(0)

    def writerows(self, rows):
        for row in rows:
            self.writerow(row)


def write_track_data_to_csv(data, destination, meta=None):
    """
    Serialize Track namedtuples to CSV

    Args:
        data (iterable): iterable of Track namedtuples
        destination (str or write-able): path or fileobj to write CSV into
        meta(dict): dict of metadata (discarded due to CSV; for compatibility)
    """
    log.debug("Writing track data to %r" % destination)
    def _write_csv(f):
        writer = UnicodeCSVWriter(f, quoting=csv.QUOTE_ALL)
        writer.writerow(Track._fields)
        writer.writerows(data)
    if hasattr(destination, 'write'):
        _write_csv(destination)
    else:
        with open(destination, 'w') as f:
            _write_csv(f)


def json_track_to_unicode_csv(source, dest):
    """
    Convert JSON Track data to Unicode CSV
    (one-off to avoid making another 300+ requests this time)

    Args:
        source (str): path to source JSON file
        dest (str): path to dest CSV file

    """
    with codecs.open(source, 'r', encoding='utf-8') as f:
        data = json.load(f)
    items = data['tracks']

    def _get_values(item):
        for field in Track._fields:
            yield item[field]
    data = [Track(*_get_values(item)) for item in items]
    write_track_data_to_csv(data, dest)



def backup_lfm(username, password, destination, max_pages=None):
    """
    Backup Last.fm data for the specified user into the destination directory

    Args:
        username (str): Last.fm username
        password (str): Last.fm password
        destination (str): path of output directory to write into

    """
    s = build_requests_session()
    s = login_lastfm(s, username, password)
    data = extract_track_data(s, username, max_pages=max_pages)
    data = list(data)
    if not os.path.exists(destination):
        os.makedirs(destination)

    dest_json_file = os.path.join(destination, 'tracks.json')
    write_track_data_to_json(data, dest_json_file, {'username': username})
    dest_csv_file = os.path.join(destination, 'tracks.csv')
    write_track_data_to_csv(data, dest_csv_file)
    return {'json':dest_json_file, 'csv':dest_csv_file}



import unittest
class Test_backup_lfm(unittest.TestCase):
    def setUp(self):
        import os
        self.tmpdir = os.path.join('.', 'tmp')
        if not os.path.exists(self.tmpdir):
            os.makedirs(os.path.join('.', 'tmp'))
        setup_http_debugging()

    def test_build_requests_session(self):
        s = build_requests_session()
        self.assertTrue(s)

    def test_login(self):
        s = build_requests_session()
        s = login_lastfm(s, USERNAME, PASSWORD)
        self.assertTrue(s)
        # TODO
        #log.debug(bs4.BeautifulSoup(s._login_resp.content).find('article'))

    @staticmethod
    def _read_track_html():
        TRACK_DATA = os.path.join('.', 'testdata', 'trackdata.html')
        with codecs.open(TRACK_DATA, encoding='utf-8') as f:
            html = f.read()
        return html

    def test_extract_tracks(self):
        html = Test_backup_lfm._read_track_html()
        data = extract_tracks(html)
        data = list(data)
        self.assertTrue(data)
        #for track in data:
        #    print(track)
        sys.stdout.flush()

    def test_write_tracks_json(self):
        html = Test_backup_lfm._read_track_html()
        data = extract_tracks(html)
        data = list(data)
        import StringIO
        output = StringIO.StringIO()
        write_track_data_to_json(data, output, {'username':'test_data'})
        output.seek(0)
        #sys.stdout.flush()
        #print(output.read())
        #sys.stdout.flush()
        # TODO
        dest = os.path.join(self.tmpdir, 'tracks.json')
        write_track_data_to_json(data, dest, {'username':'test_data'})

    def test_write_tracks_csv(self):
        html = Test_backup_lfm._read_track_html()
        data = extract_tracks(html)
        data = list(data)
        import StringIO
        output = StringIO.StringIO()
        write_track_data_to_csv(data, output, {})
        output.seek(0)
        #sys.stdout.flush()
        #print(output.read())
        #sys.stdout.flush()
        # TODO
        dest = os.path.join(self.tmpdir, 'tracks.csv')
        write_track_data_to_csv(data, dest, {})

    def test_backup_lfm(self):
        backup_lfm(USERNAME, PASSWORD, './testdata', max_pages=3)


def main(*args):
    import logging
    import optparse

    prs = optparse.OptionParser(usage="%prog : args")

    prs.add_option('-u', '--username',
                    dest='username',
                    action='store',)
    prs.add_option('-p', '--password',
                    dest='password',
                    action='store')

    prs.add_option('-o', '--output-directory',
                    dest='output_directory',
                    action='store',
                    default='./output')

    prs.add_option('--max-pages',
                    dest='max_pages',
                    action='store',
                    help="Not logged in: 50 pages max")

    prs.add_option('-v', '--verbose',
                    dest='verbose',
                    action='store_true',)
    prs.add_option('-q', '--quiet',
                    dest='quiet',
                    action='store_true',)
    prs.add_option('-t', '--test',
                    dest='run_tests',
                    action='store_true',)

    args = args and list(args) or sys.argv[1:]
    (opts, args) = prs.parse_args()

    if not opts.quiet:
        logging.basicConfig()

        if opts.verbose:
            logging.getLogger().setLevel(logging.DEBUG)
            setup_http_debugging()

    if opts.run_tests:
        sys.argv = [sys.argv[0]] + args
        import unittest
        sys.exit(unittest.main())

    username = opts.username
    password = opts.password
    if password is None:
        password = raw_input("Password for %r: " % username)

    output_directory = opts.output_directory

    backup_lfm(username, password, output_directory, max_pages=opts.max_pages)

    return 0


if __name__ == "__main__":
    sys.exit(main())
