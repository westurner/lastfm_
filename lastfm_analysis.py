#!/usr/bin/env python
# encoding: utf-8
from __future__ import print_function
"""
lastfm_analysis
"""

import pandas
pandas

def read_tracks_csv(source):
    """
    mainfunc
    """
    df = pandas.read_csv(source, parse_dates=[0])
    return df


def read_tracks_json(source):
    raise NotImplementedError()


## output formatters
def printstr(data):
    print(data.to_string())


def lastfm_analysis(source):
    df = None
    if source.endswith('json'):
        df = read_tracks_json(source)
    elif source.endswith('csv'):
        df = read_tracks_csv(source)
    else:
        raise NotImplementedError(source)

    # Augment with a count column for resampling
    df['count'] = 1

    def loved_track_plays(df):
        return df[df['loved'] == True][['artist', 'track', 'date']]

    def loved_track_counts(df):
        _df = loved_track_plays(df).groupby(['artist','track']).size()
        _df.sort(ascending=False)
        return _df

    def by_artist(df):
        _df = df.groupby(['artist']).size()
        _df.sort(ascending=False)
        return _df

    def by_track(df, min=0):
        _df = df.groupby(['artist','track']).size()
        _df.sort(ascending=False)
        return _df[_df > min]


    dfd = df[['date', 'count']].set_index('date')

    def by_year(df):
        return dfd.resample('A', how='sum')

    def by_quarter(df):
        return dfd.resample('Q', how='sum')

    def by_month(df):
        return dfd.resample('M', how='sum')

    def by_week(df):
        return dfd.resample('W', how='sum')

    def by_day(df):
        return dfd.resample('D', how='sum')

    def by_hour(df):
        return df.groupby(df['date'].map(lambda x: x.hour)).size()

    reports = [
        ('loved track plays', loved_track_plays, [printstr]),
        ('loved track counts', loved_track_counts, [printstr]),

        ('by artist', by_artist, [printstr]),
        ('by track', by_track, [printstr]),

        ('by year', by_year, [printstr]),
        ('by quarter', by_quarter, [printstr]),
        ('by month', by_month, [printstr]),
        ('by week', by_week, [printstr]),
        ('by day', by_day, [printstr]),
        ('by hour', by_hour, [printstr]),
    ]
    for name, reportfunc, outputfuncs in reports:
        print('='*79)
        print(name)
        print('='*79)
        data = reportfunc(df)
        for outputfunc in outputfuncs:
            outputfunc(data)


import unittest
class Test_lastfm_analysis(unittest.TestCase):
    def test_lastfm_analysis(self):
        lastfm_analysis('./output/tracks.csv')


def main(*args):
    import logging
    import optparse
    import sys

    prs = optparse.OptionParser(usage="%prog : args")

    prs.add_option('-i', '--input-data',
                   dest='source',
                   default='./output/tracks.csv')

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

    if opts.run_tests:
        sys.argv = [sys.argv[0]] + args
        import unittest
        sys.exit(unittest.main())

    lastfm_analysis(opts.source)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
