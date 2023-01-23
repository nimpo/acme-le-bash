#!/bin/bash

THISSCRIPT=`readlink -f $0`
THISDIR=`dirname $THISSCRIPT`
### Load in function safely
[ "`sha1sum $THISDIR/acme.functions.sh |sed -e 's/ .*//'`" != "c320af2a126096c6a3e25c4a44e8a81b07f2d94c" ] && echo "Can't find valid acme.functions.sh" && exit 1
. $THISDIR/acme.functions.sh


#. acme.functions.sh
#---------------------------- Options

declare -a domains
AWSProfile="default" 
DEBUG=Y


while [ "$*" ]
do
  [ -z "$1" ] && shift && continue
  case "$1" in
    -e)
      shift ; emailAddress="$1" ; shift ;;
    -w) 
      warningIn "-w <path> is now -HDocRoot <path>" ; shift ; set - "-HDocRoot" "$@" ;;
    -d)
      shift ; dryRun='YES' ;;
    -v)
      shift ; set -v ;;
    -n)
      warningIn "-n is now -Hnc" ; shift ; set - "-Hnc" "$@" ;;
    -DAWS) # Use DNS with nest arg 
      checkCommands aws
      [ "$method" ] && errorIn "Can only specify one challenge type" ; method="DNS-01:AWS" ; shift
      useDNS="AWS" ;; # case $1 in -*) ;; *) AWSProfile="" ;; esac ;;
    -P)
      shift ; AWSProfile="$1" ; shift ;;
    -D)
      [ "$method" ] && errorIn "Can only specify one challenge type" ; method="DNS-01:manual" ; shift
      useDNS="manual"
      ;;
    -Hnc)
      [ "$method" ] && errorIn "Can only specify one challenge type" ; method="HTTP-01:nCat" ; shift
      useHTTP="nCat" ; nCat='YES' ;;
    -HDocRoot)
      [ "$method" ] && errorIn "Can only specify one challenge type" ; method="HTTP-01:DocRoot" ; shift
      case $1 in -*) errorIn "Method $method requires an argument." ;; *) docRoot="$1" ; shift ;; esac
      useHTTP="DocRoot" ;;
    -H)
      [ "$method" ] && errorIn "Can only specify one challenge type" ; method="HTTP-01:manual" ; shift
      useHTTP="manual" ;;
    -c)
      shift ; certLocation="`cd "$(dirname "$1")"; pwd`/`basename "$1"`" ; shift ;;
    -C)
      shift ; certChainLocation="`cd "$(dirname "$1")"; pwd`/`basename "$1"`" ; shift ;;
    -k)
      shift ; keyLocation="`cd "$(dirname "$1")"; pwd`/`basename "$1"`" ; shift ;;
    -a)
      shift ; chainLocation="`cd "$(dirname "$1")"; pwd`/`basename "$1"`" ; shift ;;
    -r)
      shift ; rootLocation="`cd "$(dirname "$1")"; pwd`/`basename "$1"`" ; shift ;;
    -U)
      shift ; regenUserKey="YES" ;;
    -u)
      shift ; userPubLocation="`cd "$(dirname "$1")"; pwd`/`basename "$1"`" ; warningIn "userPubLocation '-u' is depricated as all pubkey data is stored in user.key/userKeyLocation. This options does nothing." shift ;;
    -p)
      shift ; userKeyLocation="`cd "$(dirname "$1")"; pwd`/`basename "$1"`" ; shift ;;
    -j)
      shift ; userKIDLocation="`cd "$(dirname "$1")"; pwd`/`basename "$1"`" ; shift ;;
    -V)
      shift ; VERBOSE=1 ;;
    -h|--help)
      cat <<EOF

Usage: $0 [-e <emailAddress>] [-H|-D]{see below} [-d] [-h] [-v] [-a|c|C|k|p <path>]* <FQDN> <SAN> ...

 -d Dry run, contacts LE staging server.
 -e If emailAddress is not specified will use webmaster@FQDN.
 -h This message.
 -v some kind of verbose (set -v)

PEM/Token OUTPUT FILES
 -a <path>, intermediate CA chain output location.
 -c <path>, certificate output location.
 -C <path>, certificate and intermediate CA chain combined output location.
 -k <path>, certificate's private key output location.
 -r <path>, root CA output location.
 -p <path>, Authorisation user key output/reuse location.
 -j <path>, Authorisation user KID Token output/reuse location.
 -U <path>, Regenerate authorisation user keys even if it exists (as specified by (-p))

CHALLENGES OPTIONS
 -w Will assume a running webserver serving <path>/.well-known/acme-challenge/
    as /.well-known/acme-challenge/ for all FQAN and SANs. This script will need
    write access to this directory.
 -n Will attempt to run ncat server on port 80 via sudo.

 -H... options use HTTP-01 profile:
   -HDocRoot <path>, will add tokens to <path>/.well-known/acme-challenge/
                     (i.e. assumes a running webserver on port 80).
   -Hnc,             Attempts to set up simple tcp server on port 80 that respondes to HTTP-01 callback
                     (requires sudo).
   -Hmanual,         Spits HTTP-01 token out to terminal and lets you find a way to host it.
 -D... options use DNS-01:
 -DAWS,              Uses aws cli to update DNS record hosted in Route53.
                     Use -P to set profile to use for AWS commands (default is "default"!)
 -Dmanual            Spits DNS-01 token out to terminal and lets you find a way to update TXT record.

 -P <AWScli profile> See -DAWS.

 -w <path>,          Derpicated === -HDocRoot <path>
 -n,                 Depricated === -Hnc

ABOUT
  This executable provides a basic client to the LetsEncrypt service endpoint

  https://acme-v02.api.letsencrypt.org
  or it's staging service
  https://acme-staging.api.letsencrypt.org
  https://acme-staging-v02.api.letsencrypt.org (-d option)
  The purpose of writing this script was mainly to learn about the ACME protocol.
  Its usefulness in a production environment may therefore be limited.

LICENCE
  Copyright 2019 Michael A S Jones
  Updates Copyright 2022 Michael A S Jones

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
  https://www.rfc-editor.org/rfc/rfc8555 [Accessed 2022-11-31]
  https://tools.ietf.org/html/draft-ietf-acme-acme-07 [Accessed 2019-01-19]
  https://github.com/letsencrypt/boulder/blob/master/docs/acme-divergences.md [Accessed 2019-01-19]

CREDITS
  Written by Mike 'Mike' Jones acme2le@mike-jones.me.uk

EOF
      exit 0
      ;;
    -*)
      errorIn "Unknown option $1" ; shift ;;
    *)
      if echo "$1" | checkFQDN ; then  domains+=($1) ; else errorIn "Expecting FQDN or option flag, got '$1'" ; fi ; shift ;;
  esac
done

#---------------------------- Check for at least one domain
[ ${#domains[@]} -eq 0 ] && errorIn "Expecting at least one FQDN"

#---------------------------- Get DNS Zone Roots --- used in dns-01
if [ "$useDNS" ]
then
  declare -A Zones=()
  declare -A ZoneIDs=()
  for domain in ${domains[@]}
  do
    D="$domain"
    while echo "$D"|grep -q '\.' 
    do 
      dig "$D" soa |grep "^$D\.[[:space:]]" |grep -F "$D." |grep -q '[[:space:]]SOA[[:space:]]' && Zones[$domain]=$D && ZoneIDs[$D]="" && verbose "got Zone $D for $domain" && break # Zones: map FQDN -> Root ; ready ZoneIDs: Roots -> ""
      D=`echo "$D"|sed -e 's/^[a-z0-9-]*\.//'`
    done
  done
  if [ "$method" = "DNS-01:AWS" ]
  then
    aws --profile "$AWSProfile" --output json sts get-caller-identity > awsapi-$$.ret
    ARN=`jq -r .Arn awsapi-$$.ret` || errorIn "Cannot talk to AWS"
    ACC=`jq -r .Account awsapi-$$.ret`
    verbose "Assuming AWS ARN: $ARN"
    checkNBale
    for zoneRoot in "${!ZoneIDs[@]}"
    do
      aws --profile "$AWSProfile" --output json route53 list-hosted-zones-by-name --dns-name "$zoneRoot" 2> awsapi-$$.err >awsapi-$$.ret || errorIn "AWS says '`grep . awsapi-$$.err`'."
      ZoneIDs[$zoneRoot]=`jq -r '.HostedZones[0].Id' awsapi-$$.ret |sed -e 's#^/hostedzone/\([A-Z0-9]*\).*$#\1#' | grep '^[A-Z0-9]\{1,\}$'`
      [ "${ZoneIDs[$zoneRoot]}" ] && verbose "got AWS zone ID ${ZoneIDs[$zoneRoot]} for Zone $zoneRoot" || errorIn "Error finding $zoneRoot in this AWS account $ACC"
    done
  fi
  # Now we have mapping for domain -> it's zone, [and (if using AWS) zone -> it's AWS ZoneID. So when makeing aws UPSERTS they can be batched per zone].
fi
rm -f awsapi-$$.ret awsapi-$$.err
checkNBale

#---------------------------- KID Token location (for account URI) needed if specifying Key Location
[ "$userKeyLocation" ] && ! [ "$userKIDLocation" ] && errorIn "userKIDlocation (-j) required if using userKeyLocation (-p)"

#---------------------------- Check paths to cert and key locations are writable (non-atomic) if specified
for outfile in $certLocation $certChainLocation $keyLocation $chainLocation $userPubLocation $userKeyLocation $userKIDLocation
do
  checkFile "$outfile" || errorIn "Cannot write to $outfile"
#  echo "$outfile" | checkFile || errorIn "Cannot write to $outfile"
done

#---------------------------- Check I can put a token in docroot
[ "$docRoot" ] && ! checkFile "$docRoot/.well-known/acme-challenge/test-$$-`date +%s`" && errorIn "Cannot write to '$docRoot/.well-known/acme-challenge/'"
[ "$nCat" ] && ! sudo -n ncat --version >/dev/null 2>&1 && errorIn "Unable to run ncat via sudo"

#---------------------------- Abandon Shop if there are errors so far. This is not a daffodil.
[ ${#ERRORS[@]} -gt 0 ] && echo "There were errors during sanity checks!" && checkNBale

#---------------------------- Do this all in a private tempdir
cd `umask 0077 && mktemp -d acme.XXXX` || errorIn "Cannot make temporary directory" ;
checkNBale
verbose "cd-ed to `pwd`"

#---------------------------- Default email address
[ "$emailAddress" = "" ] && emailAddress="webmaster@$domains" && warningIn "Setting null email address to $emailAddress"

#---------------------------- Endpoints for ACME v1
acmeServiceURL='https://acme-v01.api.letsencrypt.org'
[ "$dryRun" = "YES" ] && acmeServiceURL='https://acme-staging.api.letsencrypt.org'
rootCAURL='https://cert.root-x1.letsencrypt.org/'
[ "$dryRun" ] && rootCAURL='https://cert.stg-root-x1.letsencrypt.org/'
#---------------------------- Endpoints for ACME v2
acmeServiceURL='https://acme-v02.api.letsencrypt.org'
[ "$dryRun" = "YES" ] && acmeServiceURL='https://acme-staging-v02.api.letsencrypt.org'
rootCAURL='https://letsencrypt.org/certs/isrgrootx1.pem'
[ "$dryRun" ] && rootCAURL='https://letsencrypt.org/certs/staging/letsencrypt-stg-root-x1.pem'
#####Fixme

#---------------------------- SSL Config file
createReqSSLConf $emailAddress ${domains[@]} > $domains.cnf || errorIn "Unable to create $domains.cnf"
checkNBale

#---------------------------- Generate CSR
generateCSR "$domains" || errorIn "Unable to generate CSR for $domains"
checkNBale

#[ "$VERBOSE" ] && openssl req -in $domains.csr -noout -text

#---------------------------------------------------------------------- Now we talk to Acme
# First probe service to get endpoints:
declare -A directory
curl -m 5 -o Response.ret -D ResponseHead.ret -s "$acmeServiceURL/directory"
directory[termsOfService]=`jq -r '.meta.termsOfService' Response.ret |filterHTTP`
directory[newAccount]=`jq -r '.newAccount' Response.ret |filterHTTP`
directory[newNonce]=`jq -r '.newNonce' Response.ret |filterHTTP`
directory[newOrder]=`jq -r '.newOrder' Response.ret |filterHTTP`
directory[revokeCert]=`jq -r '.revokeCert' Response.ret |filterHTTP`
# for x in "${!directory[@]}"; do printf "[%s]=%s\n" "$x" "${directory[$x]}" ; done

# Get and store terms file because why not?
[ "${directory[termsOfService]}" ] && curl -m 5 -s -O "${directory[termsOfService]}"

#--------------------------------------- Agree to terms and create an Account (new get KID) Or use previous user.key and KID

if [ "$regenUserKey" ] || [ ! "$userKeyLocation" ] || [ ! -e "$userKeyLocation" ] # If need to create a new account then
then
  verbose "Agreeing to terms and getting AuthZ"
  genRSAKey user.key || errorIn "Unable to generate user.key"
  JWK=`genJWK user.key`
  JWS='{"alg":"RS256","jwk":'"$JWK"'}' ## NB Alphabetical and no spaces
  SignedJSONPayload=`genJWS '{"termsOfServiceAgreed":true,"contact":["mailto:'$emailAddress'"]}' "$JWS" "${directory[newAccount]}"`
  # LE v2 acme needs "Content-Type: application/jose+json" header or else!
  curl -m 5 -s -H "Content-Type: application/jose+json" -o Response.ret -D ResponseHead.ret -d "$SignedJSONPayload" "${directory[newAccount]}" ## New Endpoint in v2 we looked it up this time
#used in JWS json web signature
##########  KID=`awk '/^Location:[[:space:]]/ {print $2}' ResponseHead.ret | filterHTTP`
  ReplayNonce=`getHTTPHeader replay-nonce ResponseHead.ret` # No need to get new nonce for layer #!!!!!!!!!!!!!!!!!!!!!!
  KID=`getHTTPHeader location ResponseHead.ret | filterHTTP` || errorIn "No Account URL returned from ${directory[newAccount]}"
  echo "$KID" > user.kid  
  # LE acme v2 now uses key stored by reference so update headerJSON
  JWK='{"alg":"RS256","kid":"'$KID'"}'
  if [ "$userKeyLocation" ] # If user.key (and user.kid see earlier check) are supposed to be stored elsewhere on system 
  then
    DATE=`date +%s`
    [ -e "$userKeyLocation" ] && mv "$userKeyLocation" "$userKeyLocation.$DATE"
    [ -e "$userKIDLocation" ] && mv "$userKIDLocation" "$userKIDLocation.$DATE"
    cp -p user.key "$userKeyLocation" || errorIn "Cannot Copy user.key to $userKeyLocation"
    cp -p user.kid "$userKIDLocation" || errorIn "Cannot Copy user.kid to $userKIDLocation"
  fi
elif [ "$userKeyLocation" ] || [ ! -e "$userKIDLocation" ]
then
  errorIn "If importing old user.key then user.kid is also required."
else
  verbose " *** Using pre-existing user key at $userKeyLocation"
  cp -p "$userKeyLocation" user.key || errorIn "unable to copy $userKeyLocation to ./user.key"
  cp -p "$userKIDLocation" user.kid || errorIn "unable to copy $userKIDLocation to ./user.kid"
  KID=`cat user.kid`
  JWK='{"alg":"RS256","kid":"'$KID'"}'
fi
checkNBale

#exit
#################################################################################################################################
#--------- Make orders for each Domain
# Can do this in one shot it turns out (was doing this in many shots before no need to specify resource as it's in url?????

#Form JSON request body
reqdomains=`echo -n '{"identifiers":[' ; printf "{\"type\":\"dns\",\"value\":\"%s\"}," "${domains[@]}" |sed -e s/,$//; echo ']}'`

SignedJSONPayload=`genJWS "$reqdomains" "$JWK" "${directory[newOrder]}" "$ReplayNonce"`
# LE v2 acme needs "Content-Type: application/jose+json" header or else!
curl -m 5 -s -H "Content-Type: application/jose+json" -o Response.ret -D ResponseHead.ret -d "$SignedJSONPayload" "${directory[newOrder]}"

ORDERURL=`getHTTPHeader location ResponseHead.ret | filterHTTP` || errorIn "No Order URL for ${directory[newOrder]}"

#################################################################################################################################
#--------- For each Domain get the Authorisaton tokens
# Firstly a finalize URL from newOrder endpoint 
# Then an associative array for each domain containing the URL to get Authorization infos
# Then for each of those get the DNS, HTTP and TLS-ALPN Tokens and URLS

#----------------------------------- Parse last response to find out how to get those tokens

i=0; # loop through array(s) in response
finalize=`jq -r .finalize Response.ret | filterHTTP`
declare -A authorizations=()
for authz in `jq -r '.authorizations[]' Response.ret`
do
  FQDN=`jq -r ".identifiers[$i].value" Response.ret|filterFQDN`
  authzURL=`echo "$authz" | filterHTTP`
  [ "$authzURL" != "" ] && [ "$FQDN" != "" ] && authorizations[$FQDN]="$authzURL"
  let i++
done

[ ${#domains[@]} -eq ${#authorizations[@]} ] || errorIn "Asked to authentincate ${#domains[@]} domains, ${#authorizations[@]} were authorized"
checkNBale

#----------------------------------- Go get those Tokens and URLS now

declare -A DNSToken=() ; declare -A HTTPToken=() ; declare -A TLSALPNToken=() ; declare -A DNSURL=() ; declare -A HTTPURL=() ; declare -A TLSALPNURL=()
for FQDN in ${domains[@]}
do
  verbose "In domain loop for $FQDN"
  SignedJSONPayload=`genJWS "" "$JWK" "${authorizations[$FQDN]}"  "$ReplayNonce"`
  curl -m 5 -s -H "Content-Type: application/jose+json" -o Response.ret -D ResponseHead.ret -d "$SignedJSONPayload" "${authorizations[$FQDN]}" || errorIn "Cannot get token for $FQDN" 
  DNSToken[$FQDN]=`jq -r '.challenges[]| select(.type == "dns-01")|.token' Response.ret |grep '^[A-Za-z0-9_-]\{1,\}$'` || warningIn "unable to get dns-01 token for $FQDN"
  HTTPToken[$FQDN]=`jq -r '.challenges[]| select(.type == "http-01")|.token' Response.ret |grep '^[A-Za-z0-9_-]\{1,\}$'` || warningIn "unable to get http-01 token for $FQDN"
  TLSALPNToken[$FQDN]=`jq -r '.challenges[]| select(.type == "tls-alpn-01")|.token' Response.ret |grep '^[A-Za-z0-9_-]\{1,\}$'` || warningIn "unable to get tls-alpn-01 token for $FQDN"
  DNSURL[$FQDN]=`jq -r '.challenges[]| select(.type == "dns-01")|.url' Response.ret |filterHTTP` || warningIn "unable to get dns-01 URL for $FQDN"
  HTTPURL[$FQDN]=`jq -r '.challenges[]| select(.type == "http-01")|.url' Response.ret |filterHTTP` || warningIn "unable to get http-01 URL for $FQDN"
  TLSALPNURL[$FQDN]=`jq -r '.challenges[]| select(.type == "tls-alpn-01")|.url' Response.ret |filterHTTP` || warningIn "unable to get tls-alpn-01 URL for $FQDN"
done
checkNBale

######################################################################
#----------------------------------- Pop those tokens in!
JWKDgstB64=`genJWK user.key |Dgst |B64`
if [ "$method" = "HTTP-01:DocRoot" ] 
then
  verbose "doing local running webserver route" 
  ! [ -d "$docRoot" ] && errorIn "No docRoot to write to" 
  for domain in ${domains[@]}
  do
    mkdir -p "$docRoot/.well-known/acme-challenge/" || errorIn "No docRoot to write to" 
    echo "${HTTPToken[$domain]}.$JWKDgstB64" > "$docRoot/.well-known/acme-challenge/${HTTPToken[$domain]}"
  done
  # taken out ncat and manual for the moment (see earlier versions for code)
elif [ "$method" = "HTTP-01:nCat" ]
then
  verbose "making makeshift nCat webserver callback"
  script=""
  for domain in ${domains[@]}
  do
    verbose "adding http://$domain:80/.well-known/acme-challenge/${HTTPToken[$domain]} to makeshift nCat server"
    script=$script'echo "$i"'" |grep -qF 'GET /.well-known/acme-challenge/${HTTPToken[$domain]} ' && /bin/echo -ne 'HTTP/1.1 200 OK\r\nContent-length: `expr ${#HTTPToken[$domain]} + ${#JWKDgstB64} + 3`\r\n\r\n${HTTPToken[$domain]}.$JWKDgstB64\r\n' && exit ; "
  done
  script='read i ; ! echo "$i" | grep -q "^GET [^ ][^ ]* HTTP/[1-9].[0-9][[:cntrl:]]$" && echo -ne "HTTP/1.1 405 Method Not Allowed\r\nAllow: GET\r\n\r\n" && exit ; '$script"echo -ne 'HTTP/1.1 404 Not Found\r\n\r\n'"
  sudo -n ncat -k -l -p 80 -c "$script" &
  sudoID=$!
  [ "$sudoID" ] || errorIn "Unable to start nCat Server for makeshift nCat webserver callback"
  sleep 2
  sudoPID=`ps --ppid $sudoID -o pid=`
  nCatID=`ps --pid $sudoPID -C ncat -o pid=`
  trap "{ sudo kill $nCatID ; exit 0 ; }" EXIT
elif [ "$method" = "DNS-01:AWS" ]
then                        # TXT in _acme-challenge.<YOUR_DOMAIN> "..."
  #--------------------------------------------Ask AWS to make changes one zone at a time. Assumes only one AWS account easier to get separate certs for separate Zones even!
  batch='{"Comment":"ACME Upsert","Changes":['
  declare -A zoneChanges=()
  for domain in ${domains[@]}
  do
    Token=`echo -n "${DNSToken[$domain]}.$JWKDgstB64" |Dgst |B64`
    verbose "Asking AWS to add the following DNS record:" "_acme-challenge.$domain 5 IN TXT \"$Token\"" 
  # lookup ZoneIDs
    zoneID="${ZoneIDs["${Zones[$domain]:-"X"}"]}" # Nested lookup we use substitute X to avoid unredirectable error
    [ "$zoneID" = "" ] && errorIn "Failed to lookup AWS ZoneId for $domain" && continue
    zoneChanges["$zoneID"]=${zoneChanges["$zoneID"]}'{"Action":"UPSERT","ResourceRecordSet":{"Name":"_acme-challenge.'$domain'","Type":"TXT","TTL":5,"ResourceRecords":[{"Value":"\"'$Token'\""}]}},'
  done
  checkNBale
  for zoneChange in ${!zoneChanges[@]} ##################################
  do 
    batch='{"Comment":"ACME Upsert for '$zoneChange'","Changes":['`echo "${zoneChanges[$zoneChange]}" | sed -e 's/,$/]}/'`
#ZoneIDs[$zoneRoot]=`aws --profile "$AWSProfile" --output json route53 list-hosted-zones-by-name --dns-name "$zoneRoot" | jq -r '.HostedZones[0].Id' |sed -e 's#^/hostedzone/\([A-Z0-9]*\).*$#\1#' | grep '^[A-Z0-9]\{1,\}$'` # That RE is a guess Can't find AWS spec
#    aws route53 change-resource-record-sets --hosted-zone-id "$zoneChange" --change-batch "$batch" |grep -q PENDING || errorIn "Unable to make change-resource-record-set(s)"
    aws --profile "$AWSProfile" --output json route53 change-resource-record-sets --hosted-zone-id "$zoneChange" --change-batch "$batch" > zoneChange.tmp
    ID=`jq -r .ChangeInfo.Id zoneChange.tmp |grep '^/change/[A-Z0-9]*$' | sed -e 's#/change/##'`
    Status=`jq -r .ChangeInfo.Status zoneChange.tmp`
    while [ "$Status" = "PENDING" ]
    do
      verbose "Change DNS record for $zoneChange is $Status"
      sleep 1
      Status=`aws --profile "$AWSProfile" --output json route53 get-change --id "$ID" |jq -r .ChangeInfo.Status`
    done
    verbose "Change DNS record for $zoneChange is $Status"
    [ "$Status" != "INSYNC" ] && errorIn "Change DNS record for $zoneChange failed."
  done
  checkNBale

  verbose "Check I can reach 8.8.8.8 for DNS query"

# At this point AWS has queued a change

  dig @8.8.8.8 letsencrypt.org +tries=1 +time=5 >/dev/null 2>&1 && GGLDNS="yes"
  i=1
  for j in 1 2 4 8 16 32 64 128 256
  do
    verbose "DNS checks; attempt $i"
    let i++
    unset TXTtest
    for domain in ${domains[@]}
    do
      Token=`echo -n ${DNSToken[$domain]}.$JWKDgstB64 |Dgst |B64`
      if [ "$GGLDNS" ] 
      then 
        verbose "Checking 8.8.8.8 for _acme-challenge.$domain TXT record"
        TXT=`dig @8.8.8.8 "_acme-challenge.$domain" TXT +short`
      else
        verbose "Checking local nameserver for _acme-challenge.$domain TXT record"
        TXT=`dig "_acme-challenge.$domain" TXT +short`
      fi
      [ "$TXT" != "\"$Token\"" ] && TXTtest="fail"
      verbose "...got TXT=$TXT"
      sleep 1
    done
    [ "$TXTtest" ] || break
    sleep $i
  done
  ! [ "$GGLDNS" ] && i=${DNSWait:-60} && verbose "Extra sleep $i seconds as cannot reach 8.8.8.8 here" && while [ $i -gt 0 ] ; do [ "$VERBOSE" ] && echo -n . ; sleep 1 ; let i-- ; done ; [ "$VERBOSE" ] && echo
elif [ "$method" = "DNS-01:manual" ]
then
  verbose "do manual DNS-01 route not implemented yet"
# TBA
  exit
elif [ "$method" = "HTTP-01:manual" ]
then
  verbose "doing manual HTTP-01 webserver route"
  echo "Place the following in your web server"
  for domain in ${domains[@]} ; do echo echo ${HTTPToken[$domain]}.$JWKDgstB64 \> http://$domain:80/.well-known/acme-challenge/${HTTPToken[$domain]} ; done
  echo "Hit Return when ready."
  read line
else
  errorIn "No method for callback"
fi
checkNBale

#############################################################################
#---------------------------- Checking back with LetsEncrypt for each domain
for domain in ${domains[@]}
do
  challengeStatus="pending"
  if [ "$useDNS" ]
  then
    SignedJSONPayload=`genJWS "{}" "$JWK" "${DNSURL[$domain]}" "$ReplayNonce"`
    curl -m 5 -s -H "Content-Type: application/jose+json" -o Response.ret -D ResponseHead.ret -d "$SignedJSONPayload" "${DNSURL[$domain]}" || errorIn "Cannot trigger Checks $domain"
    challengeStatus=`jq '.status' Response.ret | sed -e 's/"\([^"]*\)"/\1/'`
  else
    SignedJSONPayload=`genJWS "{}" "$JWK" "${HTTPURL[$domain]}" "$ReplayNonce"`
    curl -m 5 -s -H "Content-Type: application/jose+json" -o Response.ret -D ResponseHead.ret -d "$SignedJSONPayload" "${HTTPURL[$domain]}" || errorIn "Cannot trigger Checks $domain"
    challengeStatus=`jq '.status' Response.ret | sed -e 's/"\([^"]*\)"/\1/'`
  fi
done

#---------------------------- Checking back with LetsEncrypt for Order Status
for i in 1 2 4 8 16 32 60 60 60 60 
do
  verbose "Waiting another $i seconds for LetsEncrypt to respond to Domain Challenge for $domains"
  [ "$challengeStatus" != "pending" ] && break
  sleep $i
  SignedJSONPayload=`genJWS "" "$JWK" "$ORDERURL" "$ReplayNonce"`
  curl -m 5 -s -H "Content-Type: application/jose+json" -o Response.ret -D ResponseHead.ret -d "$SignedJSONPayload" "$ORDERURL" || errorIn "Cannot check order URL for $domain" 
  challengeStatus=`jq '.status' Response.ret | sed -e 's/"\([^"]*\)"/\1/'`
done
[ "$challengeStatus" != "ready" ] && [ "$challengeStatus" != "valid" ] && echo "Failed to verify $domain" >&2 && exit 1


###############################################################################
#---------------------------- Construct CSR Signing Request Payload and POST it

cSRB64=`openssl req -in $domains.csr -outform DER | B64`

SignedJSONPayload=`genJWS '{"csr":"'$cSRB64'"}' "$JWK" "$finalize" "$ReplayNonce"`
curl -m 5 -s -H "Content-Type: application/jose+json" -o Response.ret -D ResponseHead.ret -d "$SignedJSONPayload" "$finalize" || errorIn "Cannot check order URL for $domain" 
CertURL=`jq '.certificate' Response.ret |filterHTTP`

SignedJSONPayload=`genJWS "" "$JWK" "$CertURL" "$ReplayNonce"`
curl -m 5 -s -H "Content-Type: application/jose+json" -o Response.ret -D ResponseHead.ret -d "$SignedJSONPayload" "$CertURL" || errorIn "Cannot check order URL for $domain"
cat Response.ret > $domains.crt

[ "$cALocationURI" ] && curl -s -H 'Accept: application/pkix-cert' -o cacert.der "$cALocationURI" && openssl x509 -in cacert.der -inform DER > $domains.cacerts

checkNBale

#openssl x509 -in "$domains.crt" -noout -subject

############################################
#---------------------------- Obtain Root CA
# From known authoirative source
#curl -m 5 -s -H 'Accept: application/pkix-cert' -o caroot.der $rootCAURL
#openssl x509 -in caroot.der -inform DER > caroot.crt
curl -m 5 -s -H 'Accept: application/x-pem-file' -o caroot.crt "$rootCAURL" || warningIn "Unable to obtain Root CA"

###############################################################################
#------------------------------------------------------Format Certs for Output
CERTDOMAIN=`cat $domains.crt | splitCerts` || errorIn "Cannot split certificates from LetsEncrypt"
checkNBale
stashHashNoClash caroot.crt $CERTDOMAIN/Root

mkdir backup && chmod 0700 backup
[ "$certLocation" ]      && ( [ ! -e "$certLocation" ] || cp -p $certLocation backup/ )            && cat $domains.crt | splitCerts 0 0 > $certLocation
[ "$certChainLocation" ] && ( [ ! -e "$certChainLocation" ] || cp -fp $certChainLocation backup/ ) && constructChain $CERTDOMAIN/$CERTDOMAIN.pem $CERTDOMAIN > $certChainLocation
[ "$chainLocation" ]     && ( [ ! -e "$chainLocation" ] || cp -fp $chainLocation backup/ )          && constructChain $CERTDOMAIN/$CERTDOMAIN.pem $CERTDOMAIN | splitCerts 1 > $chainLocation
[ "$rootLocation" ]      && ( [ ! -e "$rootLocation" ] || cp -fp $rootLocation backup/ )            && cat caroot.crt > $rootLocation
umask 0077
[ "$keyLocation" ]       && ( [ ! -e "$keyLocation" ] || cp -fp $keyLocation backup/ )             && cat $domains.key > $keyLocation
rmdir backup # remove if empty

