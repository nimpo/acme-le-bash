#!/bin/bash
THISSCRIPT=`readlink -f $0`
THISDIR=`dirname $THISSCRIPT`

# This is the call to execute the certificate request
function reqfunction () {
  $THISDIR/acme.sh -C $1 -k $2 $VERBOSE -DAWS -P personalDNS -d -e dr.mike.jones@gmail.com ${FQDNS[@]}
} 

### Load in function safely
[ "`sha1sum $THISDIR/acme.functions.sh |sed -e 's/ .*//'`" != "ba6e16d9470f1d0150204d81ddcdba1b3226060e" ] && echo "Can't find valid acme.functions.sh" && exit 1
. $THISDIR/acme.functions.sh

#System environment
PATH="/bin:/usr/bin"

declare -a FQDNS=()
TRUSTPATH="/etc/ssl/certs" # Default system path
RENEWAL=28

while [ "$1" ]
do
  case "$1" in
    -cert)   shift ; CERTPATH="$1"  ; shift ;;
    -key)    shift ; KEYPATH="$1"   ; shift ;;
    -capath) shift ; TRUSTPATH="$1" ; shift ;;
    -v) VERBOSE="-V" ; shift ;;
    -d) DEBUG="Yes" ; shift ;;
    -D) DRYRUN="Yes" ; shift ;;
    -c) COPY="Yes" ; [ ${#FQDNS[@]} -gt 1 ] && errorIn "copy (-c) is no use if multiple FQDNS are also specified" ; shift ;;
    -proxy) shift ; export http_proxy="$1" && export=https_proxy="$1" ; shift ;;
    *) echo "$1" | checkFQDN && FQDNS+=($1) || errorIn "$1 not an FQDN" ; [ "$COPY" ] && [ ${#FQDNS[@]} -gt 1 ] && errorIn "copy (-c) is no use if multiple FQDNS are also specified"; shift ;;
  esac
done

curl -w5 -Iv https://letsencrypt.org >/dev/null 2>&1 || errorIn "Cannot reach letsencrypt.org via https. Use environment https_proxy or -proxy option"
checkFile "$CERTPATH" || errorIn "Cannot write to $CERTPATH"
checkFile "$KEYPATH" || errorIn "Cannot write to $KEYPATH"
[ -d "$TRUSTPATH" ] || errorIn "Trust store required"
[ ${#ERRORS[@]} -gt 0 ] && echo "Usage $THISSCRIPT -cert <fullPathToCert> -key <fullPathToKey> [-capath /etc/ssl/certs] [-v|-d|-D|-c] [-proxy <URL>] <FQDN>..." && echo "v=verbose, d=debug, D=Dryrun, c=Copy FQDNs in cert."

checkNBale

# Construct FQDNS if Copy selected


###########

###################
# Main Section
#

# Work in local temp directory
WorkingDir=`mktempdir` || errorIn "Cannot create working directory here."
cd "$WorkingDir"

# Trap exit and remove tempdir -- FIXME un-echo to enable 
function finish {
  cd ..
  echo deltempdir "$WorkingDir"  
}
trap finish EXIT

# Copying cert names if copy requested on commandline
if [ "$COPY" ]
then
  getServerCert "${FQDNS[0]}" > tmpcert.pem 2>/dev/null || cp $CERTPATH tmpcert.pem 2>/dev/null
  FQDNS=(`getNames tmpcert.pem`) || errorIn "Cannot copy Names from any existing certificates"
  echo "changing FQDNs to ${FQDNS[@]}"
fi
checkNBale

# 1, what cert is the server using?
# Start with checks for certificate actually installed
for fqdn in ${FQDNS[@]}
do
  debug "DNScheck "'"'"$fqdn +short"'"'
  printf "%-60s" "Check $fqdn is resolvable"
  ! DNScheck "$fqdn" && echo " [ FAIL ]" && errorIn "$fqdn is unresolvable" && continue
  echo " [  OK  ]"
done
checkNBale

# If we got here then we can resolve servers

# Check local cert and key returns 0 if cert at $1 is 
function localcertchecks () { # $1 is cert $2... are FQDNS to check against
  for CERT in "$1"
  do
    shift
    debug "check '$CERT' exists"
    printf "%-60s" "Checking cert is on filesystem"
    ! [ -e "$CERT" ] && echo " [ FAIL ]" && warningIn -q "Cert: "$CERT" does not exist (yet)" && continue || echo " [  OK  ]"

    debug "checkNames $CERT $@"
    printf "%-60s" "Checking certificate matched expected fqdns"
    ! checkNames "$CERT" $@ && warningIn -q "Cert: "$CERT" does not match all of $@" && echo " [ FAIL ]" || echo " [  OK  ]"

    debug "checkCertFormat "'"'"$CERT"'"'
    printf "%-60s" "Checking format of certificate"
    ! Format=`checkCertFormat "$CERT"` && echo " [ $Format ]" && warningIn -q "Cannot determine certificate format for $CERT" && continue || echo " [ $Format ]" 

#    debug "splitCerts "'"'"${fqdn}.chain.pem"'"'
#    printf "%-60s" "Splitting pulled certificate chain"
#    ! CertName=`cat "$CERT" | splitCerts` && echo " [ FAIL ]" && warningIn "Cannot separate cert chain into cert and CAs" && continue || echo " [  OK  ]"

    debug "checkCertChain '$CERT' '$TRUSTPATH' '$CERT'"
    printf "%-60s" "Checking if certificate $CERT is trusted locally"
    ! checkCertChain "$CERT" "$TRUSTPATH" "$CERT" && echo " [ FAIL ]" && warningIn -q "$CERT has no trust anchors in '$TRUSTPATH'" && continue || echo " [  OK  ]"

    debug "checkDates $CERT $RENEWAL"
    printf "%-60s" "Checking if local certificate is ok for time"
    ! CertTimeCheck=`checkDates $CERT $RENEWAL` && echo " [ $CertTimeCheck ]" && warningIn -q "Leaf certificate at $CERT is not within time validity window" && continue || echo " [ $CertTimeCheck ]"

    return # if we get here local cert is in good nick
  done
  return 1
}

function certkeychecks () {
  for LOCALKEY in "$2"
  do
    for LOCALCERT in "$1"
    do
      debug "check '$LOCALKEY' exists"
      printf "%-60s" "Checking key is on filesystem"
      ! [ -e "$LOCALKEY" ] && echo " [ FAIL ]" && warningIn -q "Local key: "$LOCALKEY" does not exist (yet)" && GET=1 && continue || echo " [  OK  ]"
      debug "check '$LOCALKEY' exists"
      printf "%-60s" "Checking key 'LOCALKEY' is on filesystem"
      ! checkKeyCertMatch "$LOCALKEY" "$LOCALCERT" && echo "[ FAIL ]" && warningIn -q "Local key: '$LOCALKEY' does not match Local Cert: '$LOCALCERT'" && GET=1 && continue || echo "[ OK ]"
      return # if we get here local cert and key match
    done
  done
  return 1
}

# Get Cert from TLS, check it and crosscheck with local
function remotechecks () { # $1 is localcert
  local Fails=0
  for LOCALCERT in $1
  do
    shift
    for fqdn in $@
    do
      let Fails++
      debug "curl -k -m5 'https://$fqdn' >/dev/null 2>&1"
      printf "%-60s" "Checking server at $fqdn functions"
      ! curl -k -m5 https://$fqdn >/dev/null 2>&1 && echo " [ FAIL ]" && errorIn "$fqdn has no https server on 443" && continue || echo " [  OK  ]"
      debug "getServerCert '$fqdn' > '${fqdn}.chain.pem'"
      printf "%-60s" "Pulling certificate from https://$fqdn"
      ! getServerCert "$fqdn" > "${fqdn}.chain.pem" && echo " [ FAIL ]" && warningIn -q "Cannot retrieve certificate chain from https://$fqdn" && continue || echo " [  OK  ]"
      debug "Do Cert Generic checks '${fqdn}.chain.pem'"
      echo
      echo " --- Checking cert fetched from $fqdn ---"
      ! localcertchecks "${fqdn}.chain.pem" "${fqdn}" && printf "%-60s%s\n" " --- cert fetched from $fqdn" " [ FAIL ]" && warningIn -q "LocalCert Check for ${fqdn}.chain.pem failed" && continue || printf "%-60s%s\n" " --- cert fetched from $fqdn" " [  OK  ]"
#      debug "checkCertsMatch "'"'"${fqdn}.chain.pem"'" "'"$CERTPATH"'"'
#      printf "%-60s" "Check pulled certificate matches installed certificate"
#      ! [ -e "$CERTPATH" ] && echo "[ NONE ]" && warningIn "No Certificate at '$CERTPATH' To check ${fqdn}.chain.pem against" && continue
#      ! checkCertsMatch "${fqdn}.chain.pem" "$LOCALCERT" && echo "[ FAIL ]" && warningIn "${fqdn}.chain.pem does not match Certificate at '$LOCALCERT'" && continue || echo "[  OK  ]"
      let Fails--
    done
    return $Fails
  done
  return 1
}

#function localremotecheck () {
#  debug "checkCertsMatch '$1' '$C2'"
#  printf "%-60s" "Check pulled certificate matches installed certificate"
#  ! checkCertsMatch "$1" "$2" && echo "[ FAIL ]" && warningIn "$1 does not match Certificate at '$2'" && return 1 || echo "[  OK  ]"
#}
if remotechecks $CERTPATH ${FQDNS[@]}
then
  echo REMOTE CERTS OK No action
else
  echo
  if localcertchecks $CERTPATH ${FQDNS[@]}
  then
    echo Apache needs reconfig
  else
    echo Certs need getting
    declare -f reqfunction
    [ "$DRYRUN" ] || reqfunction newcert.pem newkey.pem
    if localcertchecks newcert.pem newkey.pem && certkeychecks newcert.pem newkey.pem
    then
      echo cp -p newcert.pem $CERTPATH
      echo cp -p newkey.pem  $KEYPATH
    else
      errorIn "Failed to get new certs"
      checkNBale
    fi
  fi
fi


