#!/usr/bin/env bash
SERVER="${1:-149.28.47.116}"
PORT="${2:-53}"
dig @$SERVER -p $PORT fast.com
dig @$SERVER -p $PORT www.google.com
dig @$SERVER -p $PORT www.facebook.com
dig @$SERVER -p $PORT telecom-transcription-service.wus2-01.telecom.devtest.telecom.srv.st.dev
