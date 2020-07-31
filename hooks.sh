#!/usr/bin/env bash

. hooks/cert-01-fortiweb/fortiweb.conf
. fortiweb.conf

# DO NOT CHANGE PARAMETERS BELOW

IS_ADOM=0
LOGGED=0
URL_VDOM=''
AUTH=$(printf $USERNAME':'$PASSWORD | base64)

function send_curl() 
{
    local  __method=$1
    local  __url=$2

    local AUTH=$(printf $USERNAME':'$PASSWORD | base64)

    local CURL="/usr/bin/curl -s -f -H 'Authorization: $AUTH'"
    CMD="$CURL -k -X $__method https://$FORTIWEB:90/api/v1.0/$__url"
}

function send_form_curl() {
    local url="$1"
    local content="$2"
    shift; shift
    local form=("$@")

    local AUTH=$(printf $USERNAME':'$PASSWORD | base64)

    local CURL="/usr/bin/curl -s -f -H 'Content-Type: $content' -H 'Authorization: $AUTH'"

    for i in "${form[@]}"; do
        CURL+=" -F ${i}"
    done

    CMD="$CURL -k -X POST https://$FORTIWEB:90/api/v1.0/$url"
}

function send_post_curl() {
    local url="$1"
    local data="$2"

    local AUTH=$(printf $USERNAME':'$PASSWORD | base64)

    local CURL="/usr/bin/curl -s -f -H 'Authorization: $AUTH'"

    CMD="$CURL -k -X POST https://$FORTIWEB:90/api/v1.0/$url -d '$data'"
}


function login() {
    echo '   + login'
    send_curl 'GET' 'System/Status/Status'
    local CMD=$CMD' || echo -1'
    local EVAL=$(eval $CMD)
    
    if [ -1 == "$EVAL" ]; then 
        echo '     + connection error !'
        return -1
    fi

    LOGGED=1

    return 0
}

function get_certificate_list() {
    echo '     + extract certificate list'
    
    send_curl 'GET' 'System/Certificates/Local'
    local CMD=$CMD' || echo -1'
    local EVAL=$(eval $CMD)
    
    if [ -1 == "$EVAL" ]; then 
        echo '     + connection error !'
        return -1
    fi
    
    echo $EVAL | jq
    
    return 0
}

function check_sni_members() {

    for row in $(echo "$MEMBERS" | jq -r '.[] | @base64'); do
        _jq() {
            echo ${row} | base64 --decode | jq -r ${1}
        }
        local SNI_DOMAIN=$(echo $(_jq '.domain'))
        if [ $DOMAIN == $SNI_DOMAIN ]; then
            SNI_ID=$(echo $(_jq '.id'))
            break
        fi
    done

    return 0
}

function check_sni() {

    echo '   + Check existant SNI certificate for '$DOMAIN

    local CURL="curl -s -X GET -k -H 'Authorization:$AUTH' 'https://$FORTIWEB:90/api/v1.0/System/Certificates/SNI'"
    local CMD=$CURL' || echo -1'
    local SNIS=$(eval $CMD)
    SNI_ID=''

    if [ -1 == "$SNIS" ]; then 
        echo '     + connection error !'
        return -1
    fi

    # encode in base64 because of space in name
    for row in $(echo "$SNIS" | jq -r '.[] | @base64'); do
        _jq() {
            echo ${row} | base64 --decode | jq -r ${1} | sed "s/\s/%20/g"
        }
        SNI_NAME=$(echo $(_jq '._id'))

        local CURL="curl -s -k -H 'Authorization:$AUTH' 'https://$FORTIWEB:90/api/v1.0/System/Certificates/SNI/$SNI_NAME/SniServerNameIndicationMember'"
        local CMD=$CURL' || echo -1'
        local MEMBERS=$(eval $CMD)
        if [ -1 == "$MEMBERS" ]; then 
            echo '     + fail to get SNI members !'
            return -1
        fi
        check_sni_members $MEMBERS
        if [[ ! -z $SNI_ID ]]; then
            break
        fi
    done

    return 0
}

function delete_sni() {
    echo '   + Deleting SNI certificate member for '$DOMAIN

    send_curl "DELETE" "System/Certificates/SNI/$SNI_NAME/SniServerNameIndicationMember/$SNI_ID"
    local CMD=$CMD' || echo -1'
    local EVAL=$(eval $CMD)

    if [ -1 == "$EVAL" ]; then
        echo '     + connection error !'
        return -1
    fi

    echo '   + SNI certificate member deleted for '$DOMAIN
}

function update_sni() {

    echo '   + update SNI certificate member for '$DOMAIN

    local DATA="{\"domainType\":0, \"localCertificate\": \"$DOMAIN\", \"intermediateCAGroup\": \"Lets Encrypt CA Group\", \"certificateVerify\":\"\", \"domain\":\"$DOMAIN\"}"

    send_post_curl "System/Certificates/SNI/$SNI_NAME/SniServerNameIndicationMember" "$DATA"
    local CMD=$CMD' || echo -1'
    local EVAL=$(eval $CMD)

    if [ -1 == "$EVAL" ]; then 
        echo '     + connection error !'
        return -1
    fi

    echo '   + SNI certificate member updated for '$DOMAIN

}

function create_sni() {
    echo '   + creating new SNI for '$DOMAIN

    local DATA="{\"name\":\"$DOMAIN\"}"

    send_post_curl "System/Certificates/SNI" "$DATA"
    local CMD=$CMD' || echo -1'
    local EVAL=$(eval $CMD)

    if [ -1 == "$EVAL" ]; then 
        echo '     + connection error !'
        return -1
    fi

    echo '   + SNI created for '$DOMAIN

}

function check_certificates() {
    echo '   + Check existant certificate for '$DOMAIN

    send_curl "GET" "System/Certificates/Local"
    local CMD=$CMD' || echo -1'
    local CERTS_DOMAINS=$(eval $CMD)
    CERT_NAME=''

    if [ -1 == "$CERTS" ]; then
        echo '     + connection error !'
        return -1
    fi

    for row in $(echo "$CERTS_DOMAINS" | jq -r '.[] | @base64'); do
        _jq() {
            echo ${row} | base64 --decode | jq -r ${1}
        }
        CERT_DOMAIN=$(echo $(_jq '.subject') | awk -F 'CN = ' '{print $2}' | awk '{print $1}' | sed 's/\,//g')
        # echo $(_jq '.name')
        if [ "$DOMAIN" == "$CERT_DOMAIN" ]; then
            CERT_NAME=$(echo $(_jq '.name'))
            break
        fi
    done

    return
}

function delete_certificate() {
    echo '   + Deleting certificate for '$DOMAIN

    send_curl "DELETE" "System/Certificates/Local/$DOMAIN"
    local CMD=$CMD' || echo -1'
    local EVAL=$(eval $CMD)
    
    if [ -1 == "$EVAL" ]; then 
        echo '     + connection error !'
        return -1
    fi
    echo '   + Certificate deleted for '$DOMAIN
}

function import_certificate() {

    echo '   + Transforming certificate for '$DOMAIN' into crt and key file'

    NEW_CERTFILE=$(echo $CERTFILE | sed "s/cert\.pem/$DOMAIN.crt/g")
    NEW_KEYFILE=$(echo $KEYFILE | sed "s/privkey\.pem/$DOMAIN.key/g")

    openssl x509 -outform der -in $CERTFILE -out $NEW_CERTFILE
    openssl rsa -outform der -in $KEYFILE -out $NEW_KEYFILE

    echo '   + importing certificate for '$DOMAIN

    form=("type=certificate" "certificateFile=@$NEW_CERTFILE" "keyFile=@$NEW_KEYFILE")

    send_form_curl "System/Certificates/Local" "multipart/form-data" "${form[@]}"
    local CMD=$CMD' || echo -1'
    local EVAL=$(eval $CMD)

    if [ -1 == "$EVAL" ]; then 
        echo '     + connection error !'
        return -1
    fi

    echo '   + import finished for '$DOMAIN
}



function deploy_challenge() {
    local DOMAIN="${1}" TOKEN_FILENAME="${2}" TOKEN_VALUE="${3}"
    
    # This hook is called once for every domain that needs to be
    # validated, including any alternative names you may have listed.
    #
    # Parameters:
    # - DOMAIN
    #   The domain name (CN or subject alternative name) being
    #   validated.
    # - TOKEN_FILENAME
    #   The name of the file containing the token to be served for HTTP
    #   validation. Should be served by your web server as
    #   /.well-known/acme-challenge/${TOKEN_FILENAME}.
    # - TOKEN_VALUE
    #   The token value that needs to be served for validation. For DNS
    #   validation, this is what you want to put in the _acme-challenge
    #   TXT record. For HTTP validation it is the value that is expected
    #   be found in the $TOKEN_FILENAME file.

    echo ' + fortiweb hook executing: deploy_challenge'
    
    echo ' + nothing to do'
}

function clean_challenge() {
    local DOMAIN="${1}" TOKEN_FILENAME="${2}" TOKEN_VALUE="${3}"

    # This hook is called after attempting to validate each domain,
    # whether or not validation was successful. Here you can delete
    # files or DNS records that are no longer needed.
    #
    # The parameters are the same as for deploy_challenge.

    echo ' + fortiweb hook executing: clean_challenge'
    
    echo ' + nothing to do'
}

function deploy_cert() {
    local DOMAIN="${1}" KEYFILE="${2}" CERTFILE="${3}" FULLCHAINFILE="${4}" CHAINFILE="${5}" TIMESTAMP="${6}"

    # This hook is called once for each certificate that has been
    # produced. Here you might, for instance, copy your new certificates
    # to service-specific locations and reload the service.
    #
    # Parameters:
    # - DOMAIN
    #   The primary domain name, i.e. the certificate common
    #   name (CN).
    # - KEYFILE
    #   The path of the file containing the private key.
    # - CERTFILE
    #   The path of the file containing the signed certificate.
    # - FULLCHAINFILE
    #   The path of the file containing the full certificate chain.
    # - CHAINFILE
    #   The path of the file containing the intermediate certificate(s).
    # - TIMESTAMP
    #   Timestamp when the specified certificate was created.
    
    echo ' + fortiweb hook executing: deploy_cert'
    
    login
    test $LOGGED == 0 && return # Stop if not logged

    check_sni

    if [ ! -z "$SNI_ID" ]; then
        echo ' + SNI exist'
        delete_sni
    else
        echo ' + no SNI found'
        SNI_NAME=$DOMAIN
        create_sni
    fi

    check_certificates

    if [ ! -z "$CERT_NAME" ]; then
        echo ' + Certificate found'
        delete_certificate
    else
        echo ' + No certificate found'
    fi

    import_certificate
    update_sni
}

function unchanged_cert() {
    local DOMAIN="${1}" KEYFILE="${2}" CERTFILE="${3}" FULLCHAINFILE="${4}" CHAINFILE="${5}"

    # This hook is called once for each certificate that is still
    # valid and therefore wasn't reissued.
    #
    # Parameters:
    # - DOMAIN
    #   The primary domain name, i.e. the certificate common
    #   name (CN).
    # - KEYFILE
    #   The path of the file containing the private key.
    # - CERTFILE
    #   The path of the file containing the signed certificate.
    # - FULLCHAINFILE
    #   The path of the file containing the full certificate chain.
    # - CHAINFILE
    #   The path of the file containing the intermediate certificate(s).
    
    echo ' + fortiweb hook executing: unchanged_cert'
    
    echo ' + nothing to do'
}

function invalid_challenge() {
    local DOMAIN="${1}" RESPONSE="${2}"

    # This hook is called if the challenge response has failed, so domain
    # owners can be aware and act accordingly.
    #
    # Parameters:
    # - DOMAIN
    #   The primary domain name, i.e. the certificate common
    #   name (CN).
    # - RESPONSE
    #   The response that the verification server returned
    
    echo ' + fortiweb hook executing: invalid_challenge'
    
    echo ' + nothing to do'
}

function request_failure() {
    local STATUSCODE="${1}" REASON="${2}" REQTYPE="${3}"

    # This hook is called when a HTTP request fails (e.g., when the ACME
    # server is busy, returns an error, etc). It will be called upon any
    # response code that does not start with '2'. Useful to alert admins
    # about problems with requests.
    #
    # Parameters:
    # - STATUSCODE
    #   The HTML status code that originated the error.
    # - REASON
    #   The specified reason for the error.
    # - REQTYPE
    #   The kind of request that was made (GET, POST...)
    
    echo ' + fortiweb hook executing: request_failure'
    
    echo ' + nothing to do'
}

function startup_hook() {
  # This hook is called before the cron command to do some initial tasks
  # (e.g. starting a webserver).

  :
}

function exit_hook() {
  # This hook is called at the end of a dehydrated command and can be used
  # to do some final (cleanup or other) tasks.

  :
}

HANDLER="$1"; shift
if [[ "${HANDLER}" =~ ^(deploy_challenge|clean_challenge|deploy_cert|unchanged_cert|invalid_challenge|request_failure|startup_hook|exit_hook)$ ]]; then
  "$HANDLER" "$@"
fi
