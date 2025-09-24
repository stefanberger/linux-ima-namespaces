#!/usr/bin/env bash

hexstr_to_bytes()
{
  local hexstr="$1"

  echo "${hexstr}" | sed -n 's/\([[:xdigit:]]\{2\}\)/0x\1,/pg' | sed 's/,$//'
}

process()
{
  local parameterset="$1"
  local headername="$2"
  local infile="$3"

  local tg ps tc pk msg ctx valid prehash hashalg tcid tgid orig_hashalg prefixhashalgo mu

  echo "static const struct mldsa_tc ${headername}_tcs[] = {"

  for ((tg = 0; ; tg++)); do
    ps=$(jq -r .testGroups[$tg].parameterSet < "${infile}")
    [ "$ps" = "null" ] && break
    [ "$ps" != "${parameterset}" ] && continue
    prehash=$(jq -r .testGroups[$tg].preHash < "${infile}")
    tgid=$(jq -r .testGroups[$tg].tgId < "${infile}")
    for ((tc = 0; ; tc++)); do
      pk=$(jq -r .testGroups[$tg].tests[$tc].pk < "${infile}")
      [ "${pk}" = "null" ] && break
      valid=$(jq -r .testGroups[$tg].tests[$tc].testPassed < "${infile}")
      hashalg=$(jq -r .testGroups[$tg].tests[$tc].hashAlg < "${infile}")
      mu=$(jq -r .testGroups[$tg].tests[$tc].mu < "${infile}")
      [ "${mu}" = "null" ] && mu=""
      tcid=$(jq -r .testGroups[$tg].tests[$tc].tcId < "${infile}")
      msg=$(jq -r .testGroups[$tg].tests[$tc].message < "${infile}")
      [ "${msg}" = "null" ] && msg=""
      ctx=$(jq -r .testGroups[$tg].tests[$tc].context < "${infile}")
      [ "${ctx}" = "null" ] && ctx=""
      sig=$(jq -r .testGroups[$tg].tests[$tc].signature < "${infile}")
      echo "{"
      echo " .tgid = ${tgid},"
      echo " .tcid = ${tcid},"
      echo " .prehash = \"${prehash}\","
      orig_hashalg="${hashalg}"
      [ "${hashalg:0:5}" = "SHA2-" ] && hashalg="sha${hashalg:5}"
      [ "${hashalg:0:6}" = "SHAKE-" ] && hashalg="shake${hashalg:6}"
      prefixhashalgo="${hashalg}"
      [ "${hashalg:0:7}" = "sha512/" ] && { prefixhashalgo="sha512-${hashalg:7}"; hashalg="sha512"; }
      echo " .hashalg = \"${prefixhashalgo,,}\", // ${orig_hashalg}" # lower case
      #echo " .prefixhashalg = \"${prefixhashalgo,,}\"",
      echo " .valid = ${valid},"
      echo " .pk_size = ${#pk} / 2,"
      echo " .pk = (unsigned char[]){$(hexstr_to_bytes "${pk}")},"
      echo " .msg_size = ${#msg} / 2,"
      echo " .msg = (unsigned char[]){$(hexstr_to_bytes "${msg}")},"
      echo " .ctx_size = ${#ctx} / 2,"
      echo " .ctx = (unsigned char[]){$(hexstr_to_bytes "${ctx}")},"
      echo " .mu_size = ${#mu} / 2,"
      echo " .mu = (unsigned char[]){$(hexstr_to_bytes "${mu}")},"
      echo " .sig_size = ${#sig} / 2,"
      echo " .sig = (unsigned char[]){$(hexstr_to_bytes "${sig}")},"
      echo "},"
    done
  done
  echo "};"
}

process "ML-DSA-44" "ml_dsa_44" $1
process "ML-DSA-65" "ml_dsa_65" $1
process "ML-DSA-87" "ml_dsa_87" $1
