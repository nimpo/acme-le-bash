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
  for command in jq openssl curl grep /bin/echo mktemp uname sudo tr ln chmod sed bash cat xargs base64 $@
  do
    which "$command" |grep -q '^\(\.\|\)*/' || ERRORS+=("This script requires the $command command")
  done
  [ ${#ERRORS[@]} -gt 0 ] && exit 1
}
checkCommands

function errorIn () { #add argument ERRORS array
  [ "$1" ] && ERRORS+=$@ ; return
}

function warningIn () {
#  [ "$1" ] && WARNINGS+=$@ && printf " *** %s *** \n" "$@" ; return
  [ "$1" ] && printf "Warning: %s\n" "$@" ; return
}

function verbose () { # echos arguments or reveals stdout if VERBOSE is set
  [ "$VERBOSE" ] && [ "$1" ] && printf " *** %s\n" "$@"
  [ "$VERBOSE" ] && ! [ -t 1 ] && cat | sed -e 's/^/ *** /'
  return 0
}

function checkFQDN () { # Check if stdin is exactly 1 FQDN < 64 chars 
  tr '\n' '\r' |sed -e 's/\r$//' | grep -q '^[a-z0-9]\(-\{0,1\}[a-z0-9]\)*\(\.[a-z0-9]\(-\{0,1\}[a-z0-9]\)*\)*$' || return 1
}

function checkStrLength () { # Check String Length $1<=Len<=$2 (default 1<=Len and Len<=64
  grep -q '^.\{'${1:-1}','${2:-64}'\}$' || return 1
}

function filterFQDN () { # Expect FQDN but may have bad characters pipe through this to return first FQDN or nothing also returns 0 if FQDN present
  sed -e 's/\([a-z0-9_.-]*\)/\n\1\n/g' | grep '^[a-z0-9]\(-\{0,1\}[a-z0-9]\)*\(\.[a-z0-9]\(-\{0,1\}[a-z0-9]\)*\)\{1,\}$' | head -n 1 |grep .
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
  echo "$1" |grep -q '^[^/]' && echo "expecitng full path not local path $1" && return 1 # This is a local filename
  echo "$1" |grep -q '^\.\{1,2\}/' && echo "Path cannot be relative in $1" && return 1 # path is relative to this path
  echo "$1" |grep -q '/\.\./' && echo "Path cannot have relative components in $1" # path has relative components
  [ -L "$1" ] && echo "Leaf symbolic links not supported. $1 is a symbolic link" && return 1
  [ -d "$1" ] && echo "Directory found $1 when expecting filename" && return 1
  [ -f "$1" ] && [ ! -w "$1" ] && echo "Can't write to existing $1" && return 1
  [ -e "$1" ] && echo "$1 is not a file." && return 1
  [ ! -e "$outfile" ] && touch "$1" && rm "$1" && return 0
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

