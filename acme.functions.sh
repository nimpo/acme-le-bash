#!/bin/nologin
export LANG=C
export LC_ALL=C

# This is file should be sourced not executed.

# Global Arrays to hold error and warning messages
declare -a ERRORS
declare -a WARNINGS

function finish { # Print Errors and Warnings on exit Could delete acme.tmpdir but 
  [ ${#WARNINGS[@]} -gt 0 ] && printf "Warning: %s\n" "${WARNINGS[@]}"
  [ ${#ERRORS[@]} -gt 0 ] && printf "Error: %s\n" "${ERRORS[@]}"
}
trap finish EXIT

function checkNBale () {
  [ ${#ERRORS[@]} -gt 0 ] && exit 1
}

function checkCommands () { #Quick check for all commands
  for command in $@
  do
    which "$command" |grep -q '^\(\.\|\)*/' || ERRORS+=("This script requires the $command command")
  done
  [ ${#ERRORS[@]} -gt 0 ] && exit 1
}

checkCommands jq openssl curl grep /bin/echo mktemp uname sudo tr ln chmod sed bash cat xargs base64

function errorIn () { #add argument ERRORS array
  [ "$1" ] && ERRORS+=("$@") ; return
}

function warningIn () {
#  [ "$1" ] && WARNINGS+=$@ && printf " *** %s *** \n" "$@" ; return
  [ "$1" ] && printf "Warning: %s\n" "$@" >&2 ; return
}

function verbose () { # echos arguments if VERBOSE is set
  [ "$VERBOSE" ] && [ "$1" ] && printf " *** %s\n" "$@"
  return 0
}

function debug () { # echos arguments >&2 if DEBUG is set 
  [ "$DEBUG" ] && [ "$1" ] && printf " >>> %s\n" "$@" >&2
  return 0
}

function checkFQDN () { # Check if stdin is exactly 1 FQDN < 64 chars (because 64 is convention for X.509 certificates) must have valid TLD i.e. must not be only numneric (so not to overlap IPv4)
  tr '\n' '\r' |sed -e 's/\r$//' | grep '^[a-z0-9]\(-\{0,1\}[a-z0-9]\)*\(\.[a-z0-9]\(-\{0,1\}[a-z0-9]\)*\)*$' | grep -q '\.[0-9]*[a-z-][a-z0-9]*$' 
}

function checkStrLength () { # Check String Length $1<=Len<=$2 (default 1<=Len and Len<=64
  grep -q '^.\{'${1:-1}','${2:-64}'\}$' || return 1
}

function filterFQDN () { # Expect FQDN but may have bad characters pipe through this to return first FQDN or nothing also returns 0 if FQDN present
  sed -e 's/\([a-z0-9_.-]*\)/\n\1\n/g' | grep '^[a-z0-9]\(-\{0,1\}[a-z0-9]\)*\(\.[a-z0-9]\(-\{0,1\}[a-z0-9]\)*\)\{1,\}$' | head -n 1 |grep '\.[0-9]*[a-z-][a-z0-9]*$'
}

function filterHTTP () { # This is seriously not complete but good enough for the job here
                         # i.e. https?://domainname/path  --  no IP addresses, no userinfo, no port
  sed -e 's/\(https\{0,1\}:\/\/[a-zA-Z0-9_.-]\{1,\}\(\/[a-zA-Z0-9_.~%!$'"'"'()*+,;#?=@/-]*\|\)\)/\n\1\n/' |grep '^https\{0,1\}:\/\/[a-zA-Z0-9_.-]\{1,\}\(\/[a-zA-Z0-9_.~%!$'"'"'()*+,;#?=@/-]*\|\)$' | head -n 1 |grep .
}

function checkEmailAddress () { # Check if stdin is exactly 1 emailAddress
  sed -e 's/\r$//g' | tr '\n' '\r' |sed -e 's/\r$//' | grep -q '^[a-zA-Z0-9!#$%&'"'"'*+/=?^_`{|}~-]\{1,\}\(\.[a-zA-Z0-9!#$%&'"'"'*+/=?^_`{|}~-]\{1,\}\)*@[a-z0-9]\(-\{0,1\}[a-z0-9]\)*\(\.[a-z0-9]\(-\{0,1\}[a-z0-9]\)*\)*$'
}

function stripPEM () { # strips out PEMS from input stream; passing then to stdout 1 per line; if $1 is set looks for that type e.g. "CERTIFICATE" or "RSA PRIVATE KEY"
  awk -v "t=${1:-.*}" '{if($0=="-----END "b"-----"){print(t==".*"?b": ":"")a;b=a=""};if(b!="")a=a$0;if($0~"^-----BEGIN "t"-----$")b=substr($0,12,length($0)-16);}'
}

function checkPrint () { # remove interesting characters so that echo safely works from command line 
  tr -d '\r\n' |grep '^[[:print:]]$'
}

function createReqSSLConf () { # Spits out a config file suitable for generating a request with CommonName=$2, SANs=$2,$3... IAN=EmailAddress (Pipe this into $2.cnf)
  Elen=${#ERRORS[@]}
  echo "$1" | checkEmailAddress || errorIn "Email Address $1 not valid"
  for fqdn in ${@:2}
  do
    echo "$fqdn" | checkFQDN || errorIn "FQDN $1 not valid"
    echo "$fqdn" | checkStrLength || errorIn "FQDN $1 too long"
  done
  [ ${#ERRORS[@]} -ne $Elen ] && return 1
  cat <<EOF
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
commonName_default              = $2
commonName_max                  = 64
[ v3_req ]
basicConstraints                = CA:FALSE
keyUsage                        = digitalSignature, keyEncipherment, dataEncipherment
extendedKeyUsage                = serverAuth, clientAuth
subjectAltName                  = DNS:`echo "${@:2}" |sed -e 's/ /,DNS:/g'`
issuerAltName                   = email:$1
EOF
}

function genRSAKey () { # Generates 4kb RSA key 
  if [ "$1" ]
  then
    ( umask 0077 ; openssl genrsa -F4 4096 > "$1" 2>/dev/null )
  else
    openssl genrsa -F4 4096 | stripPEM "RSA PRIVATE KEY"
  fi
}

function extractPubfromRSA () { # Read key $1 spit out pub $2
  if [ "$2" ]
  then
    openssl rsa -in "$1" -pubout > "$2" 2>/dev/null 
  else 
    openssl rsa -in "$1" -pubout | stripPEM "PUBLIC KEY"
  fi
}

function generateCSR () { # Generates a CSR > $1.csr using config in $1.cnf
  echo $1 | checkFQDN || errorIn "generateCSR expects one argument an FQDN"
  ! [ -e "$1.cnf" ] && errorIn "generateCSR expects to find file FQDN.cnf" && return 1
  openssl req -new -config "$1.cnf" -keyout "$1.key" -out "$1.csr" -nodes -batch >/dev/null 2>&1
}

function checkFile () { # Takes a string--a path--to an existing or soon to be existing file and attempts to check it can be written to
  [ -z "$1" ] && echo "expecitng a string in checkFile" && return 1
  echo "$1" |grep -q '^[^/]' && echo "expecitng full path not local path $1" && return 1 # This is a local filename
  echo "$1" |grep -q '^\.\{1,2\}/' && echo "Path cannot be relative in $1" && return 1 # path is relative to this path
  echo "$1" |grep -q '/\.\./' && echo "Path cannot have relative components in $1" # path has relative components
  [ -L "$1" ] && echo "Leaf symbolic links not supported. $1 is a symbolic link" && return 1
  [ -d "$1" ] && echo "Directory found $1 when expecting filename" && return 1
  [ -f "$1" ] && [ ! -w "$1" ] && echo "Can't write to existing $1" && return 1
  [ ! -e "$1" ] && touch "$1" && rm "$1" && return 0
  [ ! -f "$1" ] && echo "$1 is not a file." && return 1
  return 0
}

function B64 () {
  base64 -w 0 | tr '+/' '-_' | tr -d =
}

function Dgst () {
  openssl dgst -sha256 -binary
}

function getNonce () {
###OLD###  curl -m 5 -sI "$acmeServiceURL/directory" | grep '^Replay-Nonce:' | sed -e 's/Replay-Nonce:[[:space:]]*//' | tr -cd 'A-Za-z0-9_-'
#Should probably use ${directory[newNonce]}
  curl -m 5 -sI "$acmeServiceURL/directory" | grep '^replay-nonce:' | sed -e 's/replay-nonce:[[:space:]]*//' | tr -cd 'A-Za-z0-9_-'
}

function genJWK () { # openssl spits out modulus as a hex string and I need a base64. That's some jiggery pokery just look at those backslashes!
                     # One for backticks, one each for the sed; one (each) for the xargs; one each for the echo -e \ \\ \\\\ \\\\\\\\...
                       # Bar | backticks is this some kind of lol?
                       # Yes sir, yes after openssl:
                       # One for the backticks; one each for the sed;
                       # One (each) for the xargs,
                       # and ones that echo's read.
  [ -e "$1" ] || return 1
  UserKeyModB64=`openssl rsa -in "$1" -noout -modulus | sed -e 's/^Modulus=//' | sed -e 's/\(..\)/\\\\\\\\x\1/g' | xargs echo -ne | B64`
  echo -n '{"e":"AQAB","kty":"RSA","n":"'$UserKeyModB64'"}'
}

function genJWS () { # Generates Java Web Signature a JSON payload for the server 1=JSON 2=JWT(template) 3=target URL     # v2 update
# We're making an RFC 7515 "JWS JSON Serialization"
# BUT include header and get error: "JWS \"header\" field not allowed. All headers must be in \"protected\" field" RTFORFC
  JSONB64=`echo -n "$1" | B64`
  JWS=$2
  URL=`echo "$3" | filterHTTP`                                                                                            # require a target URL
  [ "$4" != "" ] && Nonce="$4" || Nonce=`getNonce` || ( errorIn "Unable to get Nonce" ; return 1 )
  Nonce=`getNonce` || ( errorIn "Unable to get Nonce" ; return 1 )                                                        # Should be obatined from ${directory[newNonce]}
  ProtectionJSONB64=`echo -n "$JWS" | sed -e 's"}$",\"nonce\":\"'$Nonce'\",\"url\":\"'$URL'\"}"' | B64`                   # Addition of URL to protection (using '"' as sed delimiter as '"' not allowed in URL)
  SignatureB64=`echo -n $ProtectionJSONB64.$JSONB64 | openssl dgst -sha256 -sign user.key | B64`                          # (Signature same method)
  echo '{"payload":"'$JSONB64'","protected":"'$ProtectionJSONB64'","signature":"'$SignatureB64'"}'
}

function getHTTPHeader () { # Gets a header $1 from file $2 or stdin if $2 not set
  Header=$1
  if [ "$2" ]
  then
    ! [ -r "$2" ] && errorIn "Cannot read file '$2' to get Header '$1'" && return 1
    sed -e 's/\r$//' "$2" | awk '/^[[:space:]]/ {if(a=1) {sub(/^[[:space:]]+/, ""); printf("%s",$0) } a=0} /^'$Header':[[:space:]]/ {$1="";sub(/^[[:space:]]+/, "");printf("%s",$0);a=1}'
  else
    sed -e 's/\r$//' "$2" | awk '/^[[:space:]]/ {if(a=1) {sub(/^[[:space:]]+/, ""); printf("%s",$0) } a=0} /^'$Header':[[:space:]]/ {$1="";sub(/^[[:space:]]+/, "");printf("%s",$0);a=1}'
  fi
}

#------------Cert Functions
# getCertHash <file> ; returns openssl hash
# getIssuerHash
# isCA
#
function getCertHash () {
  openssl x509 -in "$1" -noout -hash 2>/dev/null
}

function getIssuerHash () {
  openssl x509 -in "$1" -noout -issuer_hash 2>/dev/null
}

function isCA () {
  openssl x509 -in "$1" -purpose -noout 2>/dev/null |grep -q "^SSL server CA : Yes"
}

function isRootCA () {
  isCA "$1" || return 1
  [ `getCertHash "$1"` = `getIssuerHash "$1"` ]
}

function getCertPrimaryName () {
  CertName="`openssl x509 -in "$1" -noout -nameopt multiline -subject 2>/dev/null | grep '^[[:space:]]*commonName[[:space:]]*=[[:space:]]*[a-zA-Z0-9_-]*\.[a-zA-Z0-9_.-]*$' |head -n 1|sed -e 's/^[[:space:]]*commonName[[:space:]]*=[[:space:]]*//'`"
  [ "$CertName" ] || CertName="`openssl x509 -in "$1" -noout -ext subjectAltName 2>/dev/null | grep '^[[:space:]]*DNS:[a-zA-Z0-9_-]*\.[a-zA-Z0-9_.-]*$' |head -n 1 |sed -e 's/^[[:space:]]*DNS://'`"
  [ "$CertName" ] || Certname=`getCertHash "$1" |grep '^[0-9a-f]\{8\}$'`
  [ "$CertName" ] && echo "$CertName" || return 1
}

function stashHashNoClash () {
  dir="${2:-.}" ; mkdir -p $dir
  hash=`getCertHash "$1"`
  i=0 ; while [ -e "$dir/$hash.$i" ] ; do let $i++ ; done
  cp -p "$1" "$dir/$hash.$i"
}


# Separate a concatinated pem bundle on stdin into separate PEM certs...
# If ! $1 then separate concatenated PEMS in $1 into <DNS>/<DNS>.pem <DNS>/Intermediate/<hash>.0 and <DNS>/Root/<hash>.0
#   where <DNS> is the first DNS name processed EEC in the concatenated PEM file.
#   Echos <DNS> to STDOUT
# If $1 [$2] then extracts certificate $1 -- $2 where we start counting at 0 to STDOUT
#
# splitCerts [first] [last] ### starting to read at verse 0

function splitCerts () { # Take a pem chain on stdin and split it into its components
#  [ -r "$1" ] && [ -s "$1" ] || return 1
  FirstCertName="UnNamedCert"
  Split=`mktemp -d -p.`
  cat > $Split/temp
  cd "$Split"
  awk 'BEGIN {a=0} /^-----BEGIN CERTIFICATE-----$/ {a++} {b=sprintf("%03i",a/2); if (a%2) print $0 > "tempout" b}  /^-----END CERTIFICATE-----$/ {a++}' temp
  i=0
  for temp in tempout*
  do
    if [ "$1" ]
    then # extract certain certs from chain
      [ "$2" ] || set - $1 999
      [ $i -ge $1 ] && [ $i -le $2 ] && cat "$temp"
      let i++
      rm "$temp"
    else
      hash=`getCertHash "$temp"` || continue # skip broken certs silently
      ihash=`getIssuerHash "$temp"`
      isRootCA $temp && mkdir -p Root && stashHashNoClash "$temp" Root && continue
      isCA $temp && mkdir -p Intermediate && stashHashNoClash "$temp" Intermediate && continue
      CertName=`getCertPrimaryName "$temp"` || CertName="UnNamedCert"
      mv "$temp" "$CertName.pem"
      [ "$FirstCertName" = "UnNamedCert" ] && FirstCertName="$CertName"
    fi
  done
  rm temp
  cd ..
  rmdir "$Split" 2>/dev/null && return # only returns if sucessful, i.e. we catted certs to stdout
  [ -e "$FirstCertName" ] && mv "$FirstCertName" "$FirstCertName.`date +%s`"
  mv "$Split" "$FirstCertName"
  echo "$FirstCertName"
}

function constructChain () { # $1 is cert $2... are paths to CA certs or CA cert dirs CAs must be in Openssl hash{8}.[0-9] format
  cert="$1"
  shift
  localchain=("$cert")
  i=0
  while ! isRootCA "$cert"
  do
    let i++
    issuerhash=`getIssuerHash $cert`
    unset issuer
    for issuer in `find $@ -name $issuerhash.[0-9]` # loop to get issuer
    do
      openssl verify -partial_chain -trusted "$issuer" "$cert" >/dev/null 2>&1 && ! isRootCA "$issuer" && localchain+=("$issuer") && break 
    done
    [ "$issuer" ] || break
    cert=$issuer
  done
  for cert in ${localchain[@]} ; do openssl x509 -in $cert ; done
}


function constructChainWithRoots () { # $1 is cert $2... are paths to CA certs or CA cert dirs CAs must be in Openssl hash{8}.[0-9] format
  cert="$1"
  shift
  localchain=("$cert")
  i=0
  while ! isRootCA "$cert"
  do
    let i++
    issuerhash=`getIssuerHash $cert`
    unset issuer
    for issuer in `find $@ -name $issuerhash.[0-9]` # loop to get issuer
    do
      openssl verify -partial_chain -trusted "$issuer" "$cert" >/dev/null 2>&1 && localchain+=("$issuer") #&& break not sure if we should break here se e.g. letsencrypt staging, therea a root and a non root CA with the came hash!
    done
    [ "$issuer" ] || break
    cert=$issuer
  done
  for cert in ${localchain[@]} ; do openssl x509 -in $cert ; done
}

#######

function systemDNSs () { # Return nameservers from system locations starting with upstream ones for systemd resolved
  local -A USED=()
  for NS in `cat /run/systemd/resolve/resolv.conf /etc/resolv.conf 2>/dev/null | awk '/^[[:space:]]*nameserver[[:space:]]{1,}[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}[[:space:]]*$/ {print $2}'`
  do
    [ ${USED[$NS]} ] && continue
    USED[$NS]="y" && echo $NS
  done
}


function DNScheck () { # Attempt to resolve FQDN(s). For Acme HTTP-01 this needs to be resolved on the WAN so callback checks from external services can reach each FQDN via IP(v4 in this case).
                       # Usage DNScheck [-g] add 8.8.8.8 and 8.8.4.4 to the list of resolvers
                       #                [-r] add nameservers from /etc/resolv/conf
                       #                [-s] add nameservers from /run/systemd/resolve/resolv.conf
                       #                [-R <path>] add nameservers from resolv.conf at <path>
                       # We could use e.g. 8.8.8.8 as this is what LetsEncrypt uses, so why so complicated? 
                       # Because 8.8.8.8 isn't always available. Particularly on the author's home setup.
                       # This is for reasons to do with forcing local resolution of FQDN to reserved 192 addresses on that network and public IP addresses in the wild,
                       # and so having to sidestep Android's massively inconvenient default to always use 8.8.8.8 as secondary DNS server where home routers only provides one DNS server via DHCP 
                       # (thanks Netgear for squashing identical secondary DNS!) via DHCP. #Grrr
  local -a NameServers=()
  local -a FQDN=()
  while [ "$1" ]
  do
    case "$1" in
      -g) NameServers+=(8.8.8.8 8.8.4.4) ; shift ;;
     -ns) shift ; NameServers+=($1) ; shift ;;
      -r) for ns in `awk '/^[[:space:]]*nameserver[[:space:]]{1,}[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}[[:space:]]*$/ {print $2}' /etc/resolv.conf`
          do NameServers+=($ns) ; done ; shift ;;
      -s) for ns in `awk '/^[[:space:]]*nameserver[[:space:]]{1,}[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}[[:space:]]*$/ {print $2}' /run/systemd/resolve/resolv.conf`
          do NameServers+=($ns) ; done ; shift ;;
      -R) shift
          [ ! -e "$1" ] && debug "DNScheck option -R <path>: path must exist" && return 1
          for ns in `awk '/^[[:space:]]*nameserver[[:space:]]{1,}[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}[[:space:]]*$/ {print $2}' "$1"`
          do NameServers+=($ns) ; done ; shift ;;
   [^-]*) if echo $1 | checkFQDN 
          then FQDN+=($1)
          else debug "dodgy FQDN "'"'"$1"'"'" in DNScheck" ; return 1
          fi
          shift ;;
       *) debug "Unknown option "'"'"$1"'"'"to DNScheck"; return 1 ;;
    esac
  done

  debug "DNScheck for `echo "${FQDN[*]}"|sed -e 's/ /, /g'`. Trying nameservers in this order `echo "${NameServers[*]}"|sed -e 's/ /, /g'`"
  local fqdn
  local ns
  local -A USED # Only check FQDN against each server once
  local OK=0
  for fqdn in ${FQDN[@]}
  do
    if [ ${#NameServers[@]} -eq 0 ]
    then
      [ "`dig "$fqdn" +short`" ] && verbose "Found $fqdn in local resolver" && OK=0 && continue
    else
      USED=()
      for ns in ${NameServers[@]}
      do
        [ ${USED[$ns]} ] && continue
        [ "`dig "@$ns" "$fqdn" +short`" ] && verbose "Found $fqdn in $ns" && continue 2
        USED[$ns]=y
      done
    fi
    verbose "$fqdn Not found in DNS lookups"
    OK=256
  done
  return $OK
}

# Check cert name of pem cert in $1 against dns names in $2 -- $N
#   checkNames <pathToCert> <dnsName> [<dnsname>]...
#
checkNames () {
  MyCERTPATH="$1"
  local OK=0
  shift
  for a in "$@"
  do
    echo "$a" | checkFQDN || return 127
    openssl x509 -in "$MyCERTPATH" -noout || return 127
    openssl x509 -in "$MyCERTPATH" -noout -ext subjectAltName |grep '^[[:space:]]*DNS:[a-zA-Z0-9_-]*\.[a-zA-Z0-9_.-]*$' |sed -e 's/^[[:space:]]*DNS://' |grep -q "^$a$" && continue
    openssl x509 -in "$MyCERTPATH" -noout -nameopt multiline -subject |grep '^[[:space:]]*commonName[[:space:]]*=[[:space:]]*[a-zA-Z0-9_-]*\.[a-zA-Z0-9_.-]*$' |sed -e 's/^[[:space:]]*commonName[[:space:]]*=[[:space:]]*//' |grep -q "^$a$" && continue
    debug "checkNames: Certificate not valid for $a"
    OK=1
  done
  return $OK
}

# Check Date of $1 certificate
#   checkDates <pathToCert> [<DaysHeadsUp>]
#
checkDates () {
  debug "checkDates $@"
  local NOTBEFOREDATE=`openssl x509 -in "$1" -noout -startdate` || return 127
  local NOTAFTERDATE=`openssl x509 -in "$1" -noout -enddate` || return 127
  local START=`echo $NOTBEFOREDATE | sed -e 's/.*=//' | xargs -i date -d '{}' +%s`
  local END=`echo $NOTAFTERDATE | sed -e 's/.*=//' | xargs -i date -d '{}' +%s`
  local NOW=`date +%s`
  local HEADSUP=`dc -e "$END ${2:-0} 86400 * - p"` || return 127
  debug "Not before: $START; Not after: $END; Heads Up: $HEADSUP; Now: $NOW"
  [ $NOW -ge $END ]     && echo "Expired" && return 1
  [ $NOW -lt $START ]   && echo "Not Yet Valid" && return 2
  [ $NOW -gt $HEADSUP ] && echo "Renew" && return
  echo "OK"
}

# Function to check Certs and Keys match
#   checkKeyCertMatch <pathToKey> <pathToCert>
#   checkCertModsMatch <pathToCert1> <pathToCert2>
#   checkCertsMatch <pathToCert1> <pathToCert2>
#
checkKeyCertMatch () {
  debug "checkKeyCertMatch $@"
  ModulusKey=`openssl rsa -in "$1" -noout -modulus` || return 127
  ModulusCert=`openssl x509 -in "$2" -noout -modulus` || return 127
  [ "$ModulusCert" ] || return 1
  [ "$ModulusCert" = "$ModulusKey" ] && return 0
}

checkCertModsMatch () { # Not necessarily identical certs just identical key material
  debug "checkKeyCertMatch $@"
  ModulusCert1=`openssl x509 -in "$1" -noout -modulus` || return 127
  ModulusCert2=`openssl x509 -in "$2" -noout -modulus` || return 127
  [ "$ModulusCert1" ] || return 1
  [ "$ModulusCert1" = "$ModulusCert2" ] && return 0
}

checkCertsMatch () {
  debug "checkKeyCertMatch $@"
  FingerprintCert1=`openssl x509 -in "$1" -noout -SHA256 -fingerprint` || return 127
  FingerprintCert2=`openssl x509 -in "$2" -noout -SHA256 -fingerprint` || return 127
  [ "$FingerprintCert1" ] || return 1
  [ "$FingerprintCert1" = "$FingerprintCert2" ] && return 0
}

# Checks first cert (first PEM in first cert with system trust roots and optional N untrusted Intermediate CAfiles
#   checkCertChain <pathToCertUnderTest> <PathToTrustedCAs> [ <pathToUntrustedCAChain> ] ...
#
checkCertChain () {
  [ -f "$2" ] && CAs=("-CAfile" "$2")
  [ -d "$2" ] && CAs=("-CApath" "$2")
  CUT="$1"
  shift 2
  debug "Checking Cert: openssl verify ${CAs[@]} ${@/#/-untrusted } $CUT"
  openssl verify ${CAs[@]} ${@/#/-untrusted } "$CUT" >/dev/null
}

# Gets all certs as published in Openssl Handshake as multiPEM
#  getServerCert <servername> [<IPaddr>]
#
getServerCert () {
  SERVER="${2:-$1}"
  debug "Obtaining TSL Cert for host: $SERVER at $1:443"
  [ "$DEBUG" ] && echo "Obtaining TSL Cert for host: $SERVER at $1:443" >&2
  echo | openssl s_client -servername "$SERVER" -showcerts -connect "$1:443" 2>/dev/null |awk 'BEGIN {a=0} /^-----BEGIN CERTIFICATE-----$/ {a=1} {if (a==1) print $0}  /^-----END CERTIFICATE-----$/ {a=0}'
}

# Check file is formatted PEM, DER or concatenated PEM
#   checkCertFormat <pathToFile>
# 
checkCertFormat () {
  NPEMS=`awk 'BEGIN {a=0;v=0} /^-----BEGIN CERTIFICATE-----$/ {a++;data=""} {b=sprintf("%03i",a/2); if (a%2) data=data $0 "\n"}  /^-----END CERTIFICATE-----$/ {a++; print data |& "openssl x509 -noout" ; ret=close ("openssl x509 -noout") ; if (ret==0) v++} END {print v}' "$1"` || return 127
  debug "NPEMS in $1 = $NPEMS"
  [ $NPEMS -eq 1 ] && echo PEM && return 0
  [ $NPEMS -gt 1 ] && echo multiPEM && return 0
  openssl x509 -in "$1" -inform DER -noout 2>/dev/null && echo DER && return 0
  echo UNKNOWN
  return 1
}

# Make a temp file / dir
#   mktempfile mktempdir
#   creates file / directory in CWD to a specific format and sends the name to STDOUT
mktempfile () {
  mktemp -p. acme.le.tmp.file.XXXXXXXX
}

mktempdir () { 
  mktemp -d -p. acme.le.tmp.dir.XXXXXXXX
}

# Delete temp file / dir as made by mktempfile / mktempdir
# Checks format before issuing delete commands; returns 0 if successful
deltempfile () {
  debug "Attempting to remove '$1'"
  echo "$1" | grep -q '\(^\|/\)acme\.le\.tmp\.file\.[a-zA-Z0-9]\{8\}$' && [ -f "$1" ] && [ -r "$1" ] || return 1
  rm "$1"
}

deltempdir () {
  debug "Attempting to remove '$1'; PWD is `pwd`"
  echo "$1" | grep -q '\(^\|/\)acme\.le\.tmp\.dir\.[a-zA-Z0-9]\{8\}$' && [ -d "$1" ] || return 1
  rm -rf "$1"
}


