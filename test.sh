#!/usr/bin/env bash
SERVER="${1:-127.0.0.1}"
PORT="${2:-65353}"
dig @$SERVER -p $PORT telecom-transcription-service.wus2-01.telecom.devtest.telecom.srv.st.dev
dig @$SERVER -p $PORT fast.com
dig @$SERVER -p $PORT www.google.com
dig @$SERVER -p $PORT www.facebook.com
dig @$SERVER -p $PORT bag.itunes.apple.com
dig @$SERVER -p $PORT ichnaea-web.netflix.com
dig @$SERVER -p $PORT nas.nebula
dig @$SERVER -p $PORT NS instigaterevolution.com
dig @$SERVER -p $PORT NS google.com
dig @$SERVER -p $PORT NS alertr.info
dig @$SERVER -p $PORT +dnssec NS cloudflare.com
