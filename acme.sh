#!/bin/bash

export LANG=C
export LC_ALL=C

#---------------------------- Options

domains=()
while [ "$1" ]
do
  case "$1" in
    -e)
      shift ; emailAddress="$1" ; shift ;;
    -w)
      shift ; docRoot="$1" ; shift ;;
    -d)
      shift ; dryRun='YES' ;;
    -v)
      shift ; set -v ;;
    -n)
      shift ; nCat='YES' ;;
    -c)
      shift ; certLocation="$1" ; shift ;;
    -C)
      shift ; certChainLocation="$1" ; shift ;;
    -k)
      shift ; keyLocation="$1" ; shift ;;
    -a)
      shift ; chainLocation="$1" ; shift ;;
    -r)
      shift ; rootLocation="$1" ; shift ;;
    -U)
      shift ; regenUserKey="YES" ;;
    -u)
      shift ; userPubLocation="$1" ; shift ;;
    -p)
      shift ; userKeyLocation="$1" ; shift ;;
    -V)
      shift ; VERBOSE=1 ;;
    -h|--help)
      cat <<EOF

Usage: $0 [-e <emailAddress>] [-w <path>|-n] [-d] [-h] [-v] [-a|c|C|k|p|u <path>]* <FQDN> <SAN> ...

 -d Dry run, contacts LE staging server.
 -e If emailAddress is not specified will use webmaster@FQDN.
 -h This message.
 -v some kind of verbose (set -v)

PEM OUTPUT FILES
 -a <path>, intermediate CA chain output location.
 -c <path>, certificate output location.
 -C <path>, certificate and intermediate CA chain combined output location.
 -k <path>, certificate's private key output location.
 -r <path>, root CA output location.
 -p <path>, Authorisation user key output location.
 -u <path>, Authorisation user pubkey output location.
 -U <path>, Regenerate authorisation user keys even if it exists (as specified by (-p))

WEB CHALLENGES OPTIONS
 -w Will assume a running webserver serving <path>/.well-known/acme-challenge/
    as /.well-known/acme-challenge/ for all FQAN and SANs. This script will need
    write access to this directory.
 -n Will attempt to run ncat server on port 80 via sudo.
 If neither -w nor -n options the script will list the URLs and corresponding
 contents required as part of the http challenge response and wait for
 confirmation to continue.

ABOUT
  This executable provides a basic client to the LetsEncrypt service endpoint
  https://acme-v01.api.letsencrypt.org
  or it's staging service 
  https://acme-staging.api.letsencrypt.org (-d).
  The purpose of writing this script was mainly to learn about the ACME protocol.
  Its usefulness in a production environment may therefore be limited.

LICENCE
  Copyright 2019 Michael A S Jones 

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

SEE ALSO
  https://tools.ietf.org/html/draft-ietf-acme-acme-07 [Accessed 2019-01-19]
  https://github.com/letsencrypt/boulder/blob/master/docs/acme-divergences.md [Accessed 2019-01-19]

CREDITS
  Written by Mike 'Mike' Jones acme1le@mike-jones.me.uk

EOF
      exit 0
      ;;
    -*)
      error="Unknown option $1; $error" ; shift ;;
    *)
      if echo "$1" | grep -q '^[a-z0-9][a-z0-9_-]*\.[a-z0-9][a-z0-9_.-]*$' ; then  domains+=($1) ; else error="Expecting FQDN or option flag, got '$1'; $error" ; fi ; shift ;;
  esac
done

#---------------------------- Check for input errors (more work here!))

[ "$domains" ] || error="Expecting at least one FQDN; $error"

for outfile in $certLocation $certChainLocation $keyLocation $chainLocation $userPubLocation $userKeyLocation
do
  echo "$outfile" |grep -q '^\(^[^/][^/]*$\|^[^/]\)' && error="expecitng full path for $outfile; $error"
  if [ -d "$outfile" ]
  then
    error="Directory found $outfile when expecting filename; $error"
  elif [ -f "$outfile" ]
  then
    [ ! -w "$outfile" ] && error="Can't write to existing $outfile; $error"
  elif [ ! -e "$outfile" ]
  then
    touch "$outfile" || error="Can't write to non-existing $outfile; $error"
  else
    error="Can't write to existing special file $outfile; $error"
  fi
done

if [ "$docRoot" ] && [ "$nCat" ]
then
  error="Cannot specify both -n and -w;"
elif [ "$docRoot" ]
then
  [ ! -d "$docRoot/.well-known/acme-challenge" ] && error="docRoot specified but $docRoot/.well-known/acme-challenge/ doesnt exist; $error"
  [ ! -w "$docRoot/.well-known/acme-challenge" ] && error="docRoot specified but cannot add challenges to $docRoot/.well-known/acme-challenge/; $error"
elif [ "$nCat" ]
then
  sudo -n ncat -h >/dev/null 2>&1 || error="Unable to run ncat via sudo; $error"
else
  manual="YES"
fi 

for command in jq openssl curl ncat grep /bin/echo mktemp uname sudo tr ln chmod sed bash cat xargs base64
do
  which $command |grep -q '^\(\.\|\)*/' || error="This script requires the $command command; $error"
done

[ "$error" ] && echo "Errors: $error" |sed -e 's/; $/./' >&2 && exit 1

#---------------------------- Do this all in a tempdir
cd `umask 0077 && mktemp -d acme.XXXX` || exit 1
[ "$VERBOSE" ] && echo " *** cd-ed to `pwd`" 

#---------------------------- Configs and Defaults

[ "$emailAddress" = "" ] && emailAddress="webmaster@$domains"
acmeServiceURL='https://acme-v01.api.letsencrypt.org'
[ "$dryRun" = "YES" ] && acmeServiceURL='https://acme-staging.api.letsencrypt.org'
rootCAURL='https://cert.root-x1.letsencrypt.org/'
[ "$dryRun" ] && rootCAURL='https://cert.stg-root-x1.letsencrypt.org/'

cat <<EOF > $domains.cnf
HOME                            = .
RANDFILE                        = \$ENV::HOME/.rnd
[ req ]
default_bits                    = 4096
default_md                      = sha256
default_keyfile                 = privkey.pem
distinguished_name              = req_distinguished_name
string_mask                     = nombstr 
req_extensions                  = v3_req
[ req_distinguished_name ]
commonName                      = Common Name
commonName_default              = $domains
commonName_max                  = 64
[ v3_req ]
basicConstraints                = CA:FALSE
keyUsage                        = digitalSignature, keyEncipherment, dataEncipherment
extendedKeyUsage                = serverAuth, clientAuth
subjectAltName                  = DNS:`echo "${domains[@]}" |sed -e 's/ /,DNS:/g'`
issuerAltName                   = email:$emailAddress
EOF

#---------------------------- Generate CSR, user and domain keys (generate or use exisiing user key as per option)
if [ "$regenUserKey" ] || [ ! "$userKeyLocation" ]
then 
  [ "$VERBOSE" ] && echo " *** Generating user key"
  ( umask 0077 ; openssl genrsa -F4 4096 > user.key 2>/dev/null ) || exit 1 
else
  [ "$VERBOSE" ] && echo " *** Using pre-existing user key at $userKeyLocation"
  cp -p $userKeyLocation user.key 
fi

[ "$VERBOSE" ] && echo " *** Extracting user public key to `pwd`/user.pub"
openssl rsa -in user.key -pubout > user.pub 2>/dev/null || exit 1

[ "$VERBOSE" ] && echo " *** Generating Domain CSR for $domains"
openssl req -new -config $domains.cnf -keyout $domains.key -out $domains.csr -nodes -batch >/dev/null 2>&1 || exit 1

[ "$VERBOSE" ] && openssl req -in $domains.csr -noout -text


#---------------------------- Get modulus from user public key and armour it; exponent is always 65537 from -F4 option, ie AQAB; Construct headerJSON

[ "$VERBOSE" ] && echo " *** Constructing userJWK, userJWKDgstB64, headerJSON"
userJWK='{"e":"AQAB","kty":"RSA","n":"'`openssl rsa -in user.key -noout -modulus | sed -e 's/^Modulus=//' | sed -e 's/\(..\)/\\\\\\\\x\1/g' | xargs echo -ne | base64 -w 0 | tr '+/' '-_' | tr -d =`'"}'
userJWKDgstB64=`echo -n $userJWK | openssl dgst -binary -sha256 | base64 -w 0 | tr '+/' '-_' | tr -d =`
headerJSON='{"alg":"RS256","jwk":'$userJWK'}'
[ "$VERBOSE" ] && echo " *** headerJSON=$headerJSON"

#########################################################################################################
#---------------------------- Create new-reg and POST it if failed new-reg, POST to reg resource returned in Link to see if still valid

#le v1 does not implement {"only-return-existing": true} in case of regJSONB64 construction if userKeyLocation and regenUserKey is not set. So we don't bother here.

[ "$VERBOSE" ] && echo " *** create new-reg and POST it"
termsOfService=`curl -m 5 -s "$acmeServiceURL/directory" | jq -r '.meta."terms-of-service"'` || exit $?
regJSONB64=`echo -n '{"agreement":"'$termsOfService'","contact":["mailto:'$emailAddress'"],"resource":"new-reg"}' | base64 -w 0 | tr '+/' '-_' | tr -d =`
regNonce=`curl -m 5 -sI "$acmeServiceURL/directory" | grep '^Replay-Nonce:' | sed -e 's/Replay-Nonce:[[:space:]]*//' | tr -cd 'A-Za-z0-9_-'` || exit $?
regProtectionJSONB64=`echo -n $headerJSON | sed -e 's/}$/,"nonce":"'$regNonce'"}/' | base64 -w 0 | tr '+/' '-_' | tr -d =`
regCSRSignatureB64=`echo -n $regProtectionJSONB64.$regJSONB64 | openssl dgst -sha256 -sign user.key | base64 -w 0 | tr '+/' '-_' | tr -d =`
regJSONPayload='{"header":'$headerJSON',"payload":"'$regJSONB64'","protected":"'$regProtectionJSONB64'","signature":"'$regCSRSignatureB64'"}'
if [ "$VERBOSE" ]
then
  echo " *** POSTING" ; echo "$regJSONPayload" ; echo " *** to $acmeServiceURL/acme/new-reg"
  curl -v -m 5 -s -o regUserResponse.ret -D regUserResponseHead.ret -d "$regJSONPayload" "$acmeServiceURL/acme/new-reg" || exit $?
else
  curl -m 5 -s -o regUserResponse.ret -D regUserResponseHead.ret -d "$regJSONPayload" "$acmeServiceURL/acme/new-reg" || exit $?
fi


if [ ! "$regenUserKey" ] && [ "$userKeyLocation" ] && grep -q '^Location: ' regUserResponseHead.ret
then
  [ "$VERBOSE" ] && echo " *** create new-reg and POST it"
  regJSONB64=`echo -n '{"resource":"reg"}' | base64 -w 0 | tr '+/' '-_' | tr -d =`
  regNonce=`curl -m 5 -sI "$acmeServiceURL/directory" | grep '^Replay-Nonce:' | sed -e 's/Replay-Nonce:[[:space:]]*//' | tr -cd 'A-Za-z0-9_-'` || exit $?
  regProtectionJSONB64=`echo -n $headerJSON | sed -e 's/}$/,"nonce":"'$regNonce'"}/' | base64 -w 0 | tr '+/' '-_' | tr -d =`
  regCSRSignatureB64=`echo -n $regProtectionJSONB64.$regJSONB64 | openssl dgst -sha256 -sign user.key | base64 -w 0 | tr '+/' '-_' | tr -d =`
  regJSONPayload='{"header":'$headerJSON',"payload":"'$regJSONB64'","protected":"'$regProtectionJSONB64'","signature":"'$regCSRSignatureB64'"}'
  mv regUserResponse.ret regUserResponse.ret.`date +%s`
  cp regUserResponseHead.ret regUserResponseHead.ret.`date +%s`
  regURL=`cat regUserResponseHead.ret |grep '^Location: [^[:space:]]*[[:space:]]*$' |sed -e 's/Location: \([^[[:space:]]*\).*/\1/'`
  if [ "$VERBOSE" ]
  then
    echo " *** POSTING" ; echo "$regJSONPayload" ; echo " *** to $regURL"
    curl -v -m 5 -s -o regUserResponse.ret -D regUserResponseHead.ret -d "$regJSONPayload" $regURL || echo $?
  else
    curl -m 5 -s -o regUserResponse.ret -D regUserResponseHead.ret -d "$regJSONPayload" $regURL || echo $?
  fi
fi

[ "$VERBOSE" ] && echo " *** checking for valid response"
cat "regUserResponse.ret" | jq '.status' | sed -e 's/"\([^"]*\)"/\1/' |grep -q '^valid$' || exit $?

##########################################################################################
#---------------------------- Create Domain new-authz and POST them and prepare challenges

declare -A challenges
declare -A challengeJSONPayload
declare -A challengeURI
for domain in ${domains[@]}
do

  [ "$VERBOSE" ] && echo " *** Create Domain $domain new-authz, POST it and prepare challenges"
  domainAuthzJSONB64=`echo -n '{"identifier":{"type":"dns","value":"'$domain'"},"resource":"new-authz"}' | base64 -w 0 | tr '+/' '-_' | tr -d =`
  domainAuthzNonce=`curl -m 5 -sI "$acmeServiceURL/directory" | grep '^Replay-Nonce:' | sed -e 's/Replay-Nonce:[[:space:]]*//' | tr -cd 'A-Za-z0-9_-'` || exit $?
  domainAuthzProtectionJSONB64=`echo -n $headerJSON |sed -e 's/}$/,"nonce":"'$domainAuthzNonce'"}/' | base64 -w 0 | tr '+/' '-_' | tr -d =`
  domainAuthzSignatureB64=`echo -n $domainAuthzProtectionJSONB64.$domainAuthzJSONB64 | openssl dgst -sha256 -sign user.key | base64 -w 0 | tr '+/' '-_' | tr -d =`
  domainAuthzJSONPayload='{"header":'$headerJSON',"payload":"'$domainAuthzJSONB64'","protected":"'$domainAuthzProtectionJSONB64'","signature":"'$domainAuthzSignatureB64'"}'
  if [ "$VERBOSE" ]
  then
    echo " *** POSTING" ; echo "$domainAuthzJSONPayload" ; echo " *** to $acmeServiceURL/acme/new-authz"
    curl -v -m 5 -s -o "domainAuthzResponse.$domain.ret" -d "$domainAuthzJSONPayload" "$acmeServiceURL/acme/new-authz" || exit $?
    echo " *** Check for status != 400 in domainAuthzResponse.$domain.ret"
  else
    curl -m 5 -s -o "domainAuthzResponse.$domain.ret" -d "$domainAuthzJSONPayload" "$acmeServiceURL/acme/new-authz" || exit $?
  fi
  cat "domainAuthzResponse.$domain.ret" | jq '.status' | sed -e 's/"\([^"]*\)"/\1/' |grep -q '^400$' && exit $?

  challenges[$domain]=`cat domainAuthzResponse.$domain.ret | jq '.challenges[] | select(.type == "http-01") | .token' | sed -e 's/"\([^"]*\)"/\1/'`
  challengeJSONB64=`echo -n '{"keyAuthorization":"'${challenges[$domain]}.$userJWKDgstB64'","resource": "challenge"}' | base64 -w 0 | tr '+/' '-_' | tr -d =`
  challengeNonce=`curl -m 5 -sI "$acmeServiceURL/directory" | grep '^Replay-Nonce:' | sed -e 's/Replay-Nonce:[[:space:]]*//' | tr -cd 'A-Za-z0-9_-'` || exit $?
  challengeProtectionJSONB64=`echo -n $headerJSON |sed -e 's/}$/,"nonce":"'$challengeNonce'"}/' | base64 -w 0 | tr '+/' '-_' | tr -d =`
  challengeSignatureB64=`echo -n $challengeProtectionJSONB64.$challengeJSONB64 | openssl dgst -sha256 -sign user.key | base64 -w 0 | tr '+/' '-_' | tr -d =`
  challengeJSONPayload[$domain]='{"header":'$headerJSON',"payload":"'$challengeJSONB64'","protected":"'$challengeProtectionJSONB64'","signature":"'$challengeSignatureB64'"}'
  challengeURI[$domain]=`cat domainAuthzResponse.$domain.ret | jq '.challenges[] | select(.type == "http-01") | .uri' | sed -e 's/"\([^"]*\)"/\1/'`

done

##################################################################################
#---------------------------- Setup webserver in preparation for domain challenges

if [ -d "$docRoot" ]
then #---------------------------- Domain Challenges in existing webserver
  for domain in ${domains[@]}
  do
    echo ${challenges[$domain]}.$userJWKDgstB64 > "$docRoot/.well-known/acme-challenge/${challenges[$domain]}"
    [ "$VERBOSE" ] && echo " *** placing '${challenges[$domain]}.$userJWKDgstB64' into $docRoot/.well-known/acme-challenge/${challenges[$domain]} for http://$domain:80/.well-known/acme-challenge/${challenges[$domain]}"
  done
elif [ "$manual" ]
then
  echo "Place the following in your web server"
  for domain in ${domains[@]} ; do echo echo ${challenges[$domain]}.$userJWKDgstB64 \> http://$domain:80/.well-known/acme-challenge/${challenges[$domain]} ; done
  echo "Hit Return when ready."
  read line
else #---------------------------- Domain Challenges in makeshift webserver
  [ "$VERBOSE" ] && echo " *** making makeshift webserver callback of at http://$domain:80/.well-known/acme-challenge/${challenges[$domain]} of ${challenges[$domain]}.$userJWKDgstB64"
  for domain in ${domains[@]}
  do
    script=$script'echo "$i"'" |grep -qF 'GET /.well-known/acme-challenge/${challenges[$domain]} ' && /bin/echo -ne 'HTTP/1.1 200 OK\r\nContent-length: `expr ${#challenges[$domain]} + ${#userJWKDgstB64} + 3`\r\n\r\n${challenges[$domain]}.$userJWKDgstB64\r\n' && exit ; "
  done

  script='read i ; ! echo "$i" | grep -q "^GET [^ ][^ ]* HTTP/[1-9].[0-9][[:cntrl:]]$" && echo -ne "HTTP/1.1 405 Method Not Allowed\r\nAllow: GET\r\n\r\n" && exit ; '$script"echo -ne 'HTTP/1.1 404 Not Found\r\n\r\n'"
  sudo -n ncat -k -l -p 80 -c "$script" &
  sudoID=$!
  [ "$sudoID" ] || exit 1
  sleep 2 
  sudoPID=`ps --ppid $sudoID -o pid=` 
  nCatID=`ps --pid $sudoPID -C ncat -o pid=` 
  trap "{ sudo kill $nCatID ; exit 0 ; }" EXIT
fi

for domain in ${domains[@]}
do
  [ "$VERBOSE" ] && echo " *** Checking we can reach domain:80"
  ! nc -w2 -z $domain 80 && echo "Failed to connect to $domain:80" >&2 && exit 1
  [ "$VERBOSE" ] && echo " *** Checking we get the correct response"
  ! curl -m 5 -s http://$domain/.well-known/acme-challenge/${challenges[$domain]} | tr -d '\r' |grep -q "^${challenges[$domain]}.$userJWKDgstB64$" && echo "Wrong Reply from http://$domain/.well-known/acme-challenge/${challenges[$domain]}" >&2 && exit 1
done

#############################################################################
#---------------------------- Checking back with LetsEncrypt for each domains

for domain in ${domains[@]}
do
  [ "$VERBOSE" ] && echo " *** Requesting LetsEncrypt to verify our http server for $domain"
  curl -m 5 -s -o challengeResponse$domain.ret -d "${challengeJSONPayload[$domain]}" "${challengeURI[$domain]}" || exit $?
  challengeStatus=`cat challengeResponse$domain.ret | jq '.status' | sed -e 's/"\([^"]*\)"/\1/'`
  [ "$VERBOSE" ] && echo "status = $challengeStatus"
  for i in 1 2 3 4 5
  do
    [ "$challengeStatus" != "pending" ] && break
    sleep $i
    mv challengeResponse$domain.ret challengeResponse$domain.ret.`date -r challengeResponse$domain.ret +%s`
    curl -m 5 -s -o challengeResponse$domain.ret "${challengeURI[$domain]}" || exit $?
    challengeStatus=`cat challengeResponse$domain.ret | jq '.status' | sed -e 's/"\([^"]*\)"/\1/'`
    [ "$VERBOSE" ] && echo "status try $i = $challengeStatus"
  done
  [ "$challengeStatus" != "valid" ] && echo "Failed to verify $domain" >&2 && exit 1
done

###############################################################################
#---------------------------- Construct CSR Signing Request Payload and POST it

cSRB64=`openssl req -in $domains.csr -outform DER | base64 -w 0 | tr '+/' '-_' | tr -d =`
cSRJSONB64=`echo -n '{"csr":"'$cSRB64'","resource":"new-cert"}' | base64 -w 0 | tr '+/' '-_' | tr -d =`
cSRNonce=`curl -m 5 -sI "$acmeServiceURL/directory" | grep ^Replay-Nonce:[[:space:]] |sed -e 's/Replay-Nonce:[[:space:]]*//' |tr -cd 'A-Za-z0-9_-'` || exit $?
cSRProtectionJSONB64=`echo -n $headerJSON |sed -e 's/}$/,"nonce":"'$cSRNonce'"}/' | base64 -w 0 | tr '+/' '-_' | tr -d =`
cSRSignatureB64=`echo -n $cSRProtectionJSONB64.$cSRJSONB64 | openssl dgst -sha256 -sign user.key | base64 -w 0 | tr '+/' '-_' | tr -d =`
cSRJSONPayload='{"header":'$headerJSON',"payload":"'$cSRJSONB64'","protected":"'$cSRProtectionJSONB64'","signature":"'$cSRSignatureB64'"}'
if [ "$VERBOSE" ]
then
  echo " *** POST CSR for signing"
  curl -v -m 5 -s -H 'Accept: application/pkix-cert' -o cSRResponse.ret -D cSRResponseHead.ret -d "$cSRJSONPayload" "$acmeServiceURL/acme/new-cert" || exit $?
else
  curl -m 5 -s -H 'Accept: application/pkix-cert' -o cSRResponse.ret -D cSRResponseHead.ret -d "$cSRJSONPayload" "$acmeServiceURL/acme/new-cert" || exit $?
fi

##########################################################################
#---------------------------- Check POST response Status and parse headers

sed -i 's/\r$//' cSRResponseHead.ret
status=`grep '^HTTP/[0-9.]* [1-5][0-9][0-9]\( \|$\)' cSRResponseHead.ret | sed -e '$!d; s/[^ ]*[ ]\([0-9]*\).*/\1/'`
! echo "$status" |grep -q '^[0-9][0-9][0-9]$' && echo "Failed to get certificate creation status" >&2 && exit 1

#---------------------------- Checking back with LetsEncrypt for certificate issuance

if [ $status -eq 202 ] || [ $status -eq 100 ] 
then
  for retry in 2 60 120 120 120
  do
    sleep $retry
    mv cSRResponse.ret cSRResponse.ret.`date -r challengeResponse$domain.ret +%s`
    mv cSRResponseHead.ret cSRResponseHead.ret.`date -r challengeResponse$domain.ret +%s`
    if [ "$VERBOSE" ]
    then
      echo " *** retry POST CSR for signing"
      curl -v -m 5 -s -H 'Accept: application/pkix-cert' -o cSRResponse.ret -D cSRResponseHead.ret -d "$cSRJSONPayload" "$acmeServiceURL/acme/new-cert" || exit $?
    else
      curl -m 5 -s -H 'Accept: application/pkix-cert' -o cSRResponse.ret -D cSRResponseHead.ret -d "$cSRJSONPayload" "$acmeServiceURL/acme/new-cert" || exit $?
    fi
    sed -i 's/\r$//' cSRResponseHead.ret
    status=`grep '^HTTP/[0-9.]* [1-5][0-9][0-9]\( \|$\)' cSRResponseHead.ret | sed -e '$!d; s/[^ ]*[ ]\([0-9]*\).*/\1/'`
    [ $status -ne 201 ] && [ $status -ne 100 ] && break
  done
fi

[ $status -ne 201 ] && echo "Failed to get cert" >&2 && exit 1

certLocationURI=`grep '^Location:[[:space:]]' cSRResponseHead.ret | sed -e 's/Location:[[:space:]]*\([]a-zA-Z0-9_.~!*'"'"'();:@&=+$,\/?#[-]*\).*/\1/'`
cALocationURI=`grep '^Link:[[:space:]]*<[]a-zA-Z0-9_.~!*'"'"'();:@&=+$,\/?#[-]*>[[:space:]]*;[[:space:]]*rel="up"' cSRResponseHead.ret |sed -e 's/Link:[[:space:]]*<\([]a-zA-Z0-9_.~!*'"'"'();:@&=+$,\/?#[-]*\)>.*/\1/'`
openssl x509 -in cSRResponse.ret -inform DER > $domains.crt


[ "$VERBOSE" ] && echo " *** Certificate received ... " && openssl x509 -in $domains.crt -noout -text

##################################################################################
#---------------------------- Try again to get certificate -- do we need this (no)
#
#[ $status -lt 200 ] && mv cSRResponse.ret cSRResponse.ret.orig && curl -m 5 -s -H 'Accept: application/pkix-cert' -o cSRResponse.ret "$certLocationURI"

########################################################################
#---------------------------- If Link "up" in header, get CA certificate
# Assume only one intermediate for now

[ "$VERBOSE" ] && echo " *** Getting Intermediate CAs"
[ "$cALocationURI" ] && curl -s -H 'Accept: application/pkix-cert' -o cacert.der "$cALocationURI" && openssl x509 -in cacert.der -inform DER > $domains.cacerts

############################################
#---------------------------- Obtain Root CA
# From known authoirative source

[ "$VERBOSE" ] && echo " *** Getting Root CA"
curl -m 5 -s -H 'Accept: application/pkix-cert' -o caroot.der $rootCAURL
openssl x509 -in caroot.der -inform DER > caroot.crt
ln -s caroot.crt `openssl x509 -in caroot.crt -noout -hash`.0


[ "$VERBOSE" ] && echo " *** Creating backup `pwd`/backup and writing new certs in place as specified"
mkdir backup
chmod 0700 backup
[ "$certLocation" ]      && cp -p $certLocation backup/      && cat $domains.crt > $certLocation
[ "$certChainLocation" ] && cp -p $certChainLocation backup/ && cat $domains.crt $domains.cacerts > $certChainLocation
[ "$keyLocation" ]       && cp -p $keyLocation backup/       && cat $domains.key > $keyLocation
[ "$chainLocation" ]     && cp -p $chainLocation backup/     && cat $domains.cacerts > $chainLocation
[ "$rootLocation" ]      && cp -p $rootLocation backup/      && cat user.key > $rootLocation
[ "$userPubLocation" ]   && cp -p $userPubLocation backup/   && cat user.pub > $userPubLocation
umask 0077
[ "$keyLocation" ]       && cp -p $keyLocation backup/       && cat $domains.key > $keyLocation
[ "$userKeyLocation" ]   && cp -p $userKeyLocation backup/   && cat user.key > $userKeyLocation
