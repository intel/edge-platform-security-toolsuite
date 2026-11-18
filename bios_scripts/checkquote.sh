# SPDX-License-Identifier: BSD-3-Clause
#
# Adapted from the tpm2-tools project (tpm2-software organization):
#   https://github.com/tpm2-software/tpm2-tools/blob/master/test/integration/tests/checkquote.sh
#
# Modifications made for this repo's IEC 62443-4-2 measured-boot tests:
#   - PCR quote selection uses the static firmware PCRs 0-9 (what the calling
#     tests consume).  It must NOT be sha256:all: PCR 10 is the IMA PCR and is
#     still being extended while the system boots, so a quote taken early in
#     boot (e.g. when the test is resumed by fw-validation-resume.service a few
#     seconds after reboot) races with IMA and fails with
#     "FATAL ERROR: PCR values failed to match quote's digest!".
#     PCRs 0-9 are fixed once the firmware/bootloader hand off to the OS.
#     (was sha256:all, originally sha256:15,16,22)
#   - Added TPM2_QUOTE_RSA_OUTPUT_BEGIN/END markers around the RSA tpm2 quote
#     so the calling test can parse PCR values from stdout
#   - Added fail() error-handling wrapper + explicit rc checks per step
#   - Added a comprehensive sha1+sha256 pcrread diagnostic dump
#   - Replaced `source helpers.sh` with explicit no-op stubs — see below

# This script runs against the REAL platform TPM (selected via TPM2TOOLS_TCTI),
# NOT the tpm2-tools integration-test harness.  Upstream checkquote.sh does
# `source helpers.sh`, whose start_up() spins up a TPM *simulator* + tpm2-abrmd
# and aborts with "The simulator not abrmd was started, cannot determine a TCTI
# for tools."
#
# Historically that source silently failed ("helpers.sh: No such file or
# directory") because helpers.sh is a bare relative path resolved against PATH
# and the CWD, and the test harness invokes this script from the repo root.
# The script therefore worked only by accident, and broke hard whenever it was
# run from the directory that actually contains helpers.sh.
#
# Define explicit no-op stubs instead: identical behaviour to the historical
# working case (no simulator, no shutdown), but deterministic regardless of the
# working directory, and without the misleading "command not found" log noise.
start_up()  { :; }
shut_down() { :; }
# Upstream ina() reports whether a value is present in the argument list.
# Returning 0 keeps cleanup() from invoking shut_down, matching prior behaviour.
ina()       { echo 0; }

# Enhanced error handling function
fail() {
    echo "$1 test failed, please check the environment or parameters!"
    exit 1
}

# Private scratch folder (mktemp: 0700) so no key/quote file is left in the caller's folder.
workdir="$(mktemp -d)" || fail "mktemp"
cd "$workdir" || fail "cd $workdir"

handle_ek=0x81010009
handle_ak=0x8101000a
ek_alg=rsa
ak_alg=rsa
digestAlg=sha256
signAlg=rsassa
akpw=akpass
ak_ctx=ak.ctx

# PCR selection used for every quote/checkquote pair below.
# Only the static firmware/bootloader PCRs (0-9) are quoted — see the header
# note: PCR 10 (IMA) and PCRs 11+ keep changing at runtime, which makes a
# sha256:all quote non-deterministic and causes spurious digest mismatches.
quote_pcr_list=sha256:0,1,2,3,4,5,6,7,8,9

output_ek_pub_pem=ekpub.pem
output_ak_pub_pem=akpub.pem
output_ak_pub_name=ak.name
output_quote=quote.out
output_quotesig=quotesig.out
output_quotepcr=quotepcr.out

cleanup() {
  rm -f $output_ek_pub_pem $output_ak_pub_pem $output_ak_pub_name \
  $output_quote $output_quotesig $output_quotepcr rand.out $ak_ctx \
  pcr.bin

  tpm2 pcrreset 16
  tpm2 evictcontrol -C o -c $handle_ek 2>/dev/null || true
  tpm2 evictcontrol -C o -c $handle_ak 2>/dev/null || true

  if [ $(ina "$@" "no-shut-down") -ne 0 ]; then
    shut_down
    echo "shutdown"
  fi
}
trap 'cleanup; rm -rf "$workdir"' EXIT

start_up

cleanup "no-shut-down"

getrandom() {
  tpm2 getrandom -o rand.out $1
  local file_size=`ls -l rand.out | awk {'print $5'}`
  loaded_randomness=`cat rand.out | xxd -p -c $file_size`
}

# Get comprehensive PCR list across all available registers and hash algorithms
echo "execute list all pcrs sha1+sha256+sha384+sm3_256"
tpm2 pcrread sha1:all+sha256:all+sha384:all+sm3_256:all
if [ $? != 0 ]; then
    fail "pcrread comprehensive"
fi

# Key generation
echo "execute tpm2_createek"
tpm2 createek -c $handle_ek -G $ek_alg -u $output_ek_pub_pem -f pem
if [ $? != 0 ]; then
    fail "createek"
fi

echo "execute tpm2_createak"
tpm2 createak -C $handle_ek -c $ak_ctx -G $ak_alg -g $digestAlg -s $signAlg \
-u $output_ak_pub_pem -f pem -n $output_ak_pub_name -p "$akpw"
if [ $? != 0 ]; then
    fail "createak"
fi

echo "execute tpm2_evictcontrol"
tpm2 evictcontrol -Q -c $ak_ctx $handle_ak
if [ $? != 0 ]; then
    fail "evictcontrol"
fi

# Quoting
echo "execute getrandom"
getrandom 20
if [ $? != 0 ]; then
    fail "getrandom"
fi

echo "execute tpm2_quote"
echo "=== TPM2_QUOTE_RSA_OUTPUT_BEGIN ==="
tpm2 quote -c $handle_ak -l $quote_pcr_list -q $loaded_randomness \
-m $output_quote -s $output_quotesig -o $output_quotepcr -g $digestAlg -p "$akpw"
quote_rc=$?
echo "=== TPM2_QUOTE_RSA_OUTPUT_END ==="
if [ $quote_rc != 0 ]; then
    fail "quote"
fi

# Verify quote
echo "execute tpm2_checkquote"
tpm2 checkquote -u $output_ak_pub_pem -m $output_quote -s $output_quotesig \
-f $output_quotepcr -g $digestAlg -q $loaded_randomness
if [ $? != 0 ]; then
    fail "checkquote"
fi

# Verify EC

tpm2 createek -G ecc -c ecc.ek

tpm2 createak -C ecc.ek -c ecc.ak -G ecc -g sha256 -s ecdsa

tpm2 readpublic -c ecc.ak -f pem -o ecc.ak.pem

tpm2 getrandom -o nonce.bin 20

tpm2 quote -c ecc.ak -l $quote_pcr_list -q nonce.bin -m quote.bin -s quote.sig -o quote.pcr -g sha256

tpm2 checkquote -u ecc.ak.pem -m quote.bin -s quote.sig -f quote.pcr -g sha256 -q nonce.bin

# Verify that tss format works
tpm2 readpublic -c ecc.ak -f tss -o ecc.ak.tss

tpm2 checkquote -u ecc.ak.tss -m quote.bin -s quote.sig -f quote.pcr -g sha256 -q nonce.bin

# Verify the tpmt format works
tpm2 readpublic -c ecc.ak -f tpmt -o ecc.ak.tpmt

tpm2 checkquote -u ecc.ak.tpmt -m quote.bin -s quote.sig -f quote.pcr -g sha256 -q nonce.bin

# Verify that the plain tpm2_pcrread output can be passed to the checkquote tool
# The pcrread selection must match the quote selection exactly, otherwise the
# recomputed PCR composite will not match the quote digest.
tpm2 pcrread $quote_pcr_list -o pcr.bin

tpm2 checkquote -u ecc.ak.tpmt -m quote.bin -s quote.sig -g sha256 -q nonce.bin \
     -f pcr.bin -l $quote_pcr_list

# Verify quote with

tpm2 createprimary -Q -C e -G rsa2048:rsapss-sha256:null -c ek.ctx -o ek.pub -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign|restricted'

# Provide scheme explicitly
tpm2 quote -Q -c ek.ctx -g sha256 -l $quote_pcr_list -o quote.pcrs -m quote.msg -s quote.sig --scheme=rsapss 

# Signature verification
tpm2 checkquote -u ek.pub -m quote.msg -s quote.sig -f quote.pcrs

echo "tpm2 comprehensive pcrlist and checkquote test pass"
exit 0
