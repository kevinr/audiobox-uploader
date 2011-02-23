#!/usr/bin/env python
# -*- coding: utf-8; -*-
#
# An Unofficial AudioBox.fm Linux Upload Script
# Usage: abup.py [options] FILES DIRS
#
# Copyright (C) 2010 Kevin Riggle <kevinr@free-dissociation.com>
#
# Incorporating multipart.py from Bolacha by Gabriel Falcão
# (see file for licensing details)
# http://github.com/gabrielfalcao/bolacha
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public
# License along with this program; if not, write to the
# Free Software Foundation, Inc., 59 Temple Place - Suite 330,
# Boston, MA 02111-1307, USA.


import urlparse, urllib, os, sys, re, httplib2, hashlib, getpass
import oauth2 as oauth
from optparse import OptionParser
import multipart

username = ''
password = ''

musicfile = '\.mp3$'
musicfile_re = re.compile(musicfile, flags=re.IGNORECASE)


conffile_name = '.abup.conf'

request_token_url = "https://audiobox.fm/oauth/request_token"
access_token_url = "https://audiobox.fm/oauth/access_token" 
authorize_url = "https://audiobox.fm/oauth/authorize"
user_url = "https://audiobox.fm/api/user"
tracks_url = "https://audiobox.fm/api/tracks"

always_prompt = False
y_regex = re.compile('y|yes', flags=re.IGNORECASE)
yn_regex = re.compile('y|yes|n|no', flags=re.IGNORECASE)

def ask_yn(prompt, default=False):
    p = ' '
    while p != '' and not yn_regex.match(p):
        p = raw_input(prompt)
        if p != '' and not yn_regex.match(p):
            print "Unrecognized input: %s" % (p,)
    
    if p == '':
        return default
    elif y_regex.match(p):
        return True
    return False


def main():
    global username, password, musicfile, musicfile_re
    global conffile_name
    global request_token_url, access_token_url, authorize_url, user_url, tracks_url
    global always_prompt, y_regex, yn_regex

    conffile = None
    try:
        conffile = open(os.path.join(os.environ['HOME'], conffile_name))
        conf = conffile.read()
        # an empty file means we should always prompt for the username and password
        if re.search(':', conf):
            username, password = conf.split(':')
        else:
            always_prompt = True
    except IOError, e:
        if e.errno != 2:    # file not found
            raise e

    usage = "Usage: %prog [options] [FILES...] [DIRS...]"
    parser = OptionParser(usage=usage)
    parser.add_option('-u', '--user', dest='user', help='your AudioBox.fm username and password', metavar='USER:PASS')
    parser.add_option('-f', '--force', dest='force_upload', action='store_true', help='force upload even if these files have been uploaded before', default=False)
    parser.add_option('-r', '--music-regex', dest='music_regex', metavar='REGEX', help="regex (case-insensitive) to use to identify appropriate music files to upload (default: '%s')" % (musicfile,))

    if len(sys.argv[1:]) == 0:
        parser.print_help()
        sys.exit(1)

    (options, args) = parser.parse_args()

    if options.user:
        username, password = options.user.split(':')
    if options.music_regex:
        musicfile = options.music_regex
        musicfile_re = re.compile(musicfile)

    force_upload = options.force_upload

    if len(args) == 0:
        print "No files or directories specified."
        sys.exit(1)


    if username == '' or password == '':
        username = raw_input('Username: ')
        password = getpass.getpass()
        if not conffile:
            if not always_prompt:
                save_p = ask_yn("Save username and password to ~/%s? [Yn] " % (conffile_name,), default=True)
                if save_p:
                    conffile = open(os.path.join(os.environ['HOME'], conffile_name), 'w')
                    conffile.write("%s:%s" % (username, password))
                    conffile.close()
                else:
                    always_prompt_p = ask_yn("Always prompt for username and password? [yN] ")
                    if always_prompt_p:
                        conffile = open(os.path.join(os.environ['HOME'], conffile_name), 'w')
                        conffile.close()

    client = httplib2.Http()
    client.add_credentials(username, password)

    resp, content = client.request(user_url, 'GET')
    if resp['status'] != '200':
        print "couldn't authenticate user '%s' with the specified password: %s" % (username, resp['status'],)
        print content
        sys.exit(1)

    print "Credentials OK."
    print "Getting tracklist..."

    resp, content = client.request(tracks_url, 'GET')
    if resp['status'] != '200':
        print "couldn't get tracklist: %s" % (resp['status'],)
        print content
        sys.exit(1)

    # assemble a dictionary whose keys are the MD5sums of already-uploaded tracks
    tracks = {}
    for h in content.split(';'):
        tracks[h] = True

    # identify files and directories
    arg_dirs = []
    arg_files = []
    for arg in args:
        try:
            f = open(arg, 'rb')
            arg_files.append(arg)
        except IOError, e:
            if e.errno == 21:   # is a directory
                arg_dirs.append(arg)
            else:
                raise(e)
        f = None

    # upload the files
    for arg_file in arg_files:
        upload_file(client, arg_file, tracks, force_upload)
                
    # walk the provided dir and enumerate all the music files
    for arg_dir in arg_dirs:
        for root, dirs, files in os.walk(arg_dir, topdown=True, followlinks=True):
            for filename in files:
                path = os.path.join(root, filename)
                upload_file(client, path, tracks, force_upload)

    sys.exit(0)


def upload_file(client, path, tracks, force):
    global tracks_url
    if musicfile_re.search(str(path)):
        f = open(path, 'rb')
        #print "considering " + str(path)
        fdata = f.read()
        fhash = md5sum(fdata)
        # audiobox currently chokes on paths with literal double-quotes, so this is a hack to avoid that
        if not '"' in path and (force or not fhash in tracks):
            print "uploading " + str(path)
            f.seek(0)    # return cursor to beginning of file
            data = {'file': f}  # for some reason this needs the original file object, so we read it twice, yay
            body = multipart.encode_multipart(multipart.BOUNDARY, data)
            headers = {'content-type': "multipart/form-data; boundary=%s" % multipart.BOUNDARY, 
                'content-length': "%d" % len(body)}
            resp, content = client.request(tracks_url, 'POST', body=body, headers=headers)
            print resp
            print content
        #else:
            #print "already uploaded, skipping"

def md5sum(data):
    md5 = hashlib.md5()
    md5.update(data)
    return md5.hexdigest()

if __name__ == '__main__':  main()

