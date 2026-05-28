#!/usr/bin/env bash
# bulk-scan.sh — Scan multiple targets against the RonwayScanner API
# Usage: ./bulk-scan.sh [API_BASE] [OUT_FILE]
# Requires: curl, jq

set -euo pipefail

API_BASE="${1:-https://ronway-api.bpxai.com}"
OUT_FILE="${2:-scan-results.json}"
DELAY=6.1   # seconds — keeps under 10 req/min rate limit

DOMAINS=(
    bdo.com.ph
    bpi.com.ph
    metrobank.com.ph
    securitybank.com
    landbank.com
    dbp.ph
    rcbc.com
    unionbankph.com
    chinabank.ph
    eastwestbanker.com
    psbank.com.ph
    pnb.com.ph
    aub.com.ph
    maybank.com.ph
    ctbcbank.com.ph
    hsbc.com.ph
    citibank.com.ph
    standardchartered.com.ph
    robinsonsbank.com.ph
    pbcom.com.ph
    sterlingbankasia.com
    bankcom.com.ph
    uobgroup.com/uobphilippines
    tonikbank.com
    gotyme.com.ph
    maya.ph
    gcash.com
    seabank.ph
    ownbank.com
    cimbbank.com.ph
    netbank.ph
    ruralbank.com.ph
    bsp.gov.ph
    stlukes.com.ph
    themedicalcity.com
    makatimed.net.ph
    asianhospital.com
    cardinalsantos.com.ph
    feudragonhospital.com.ph
    manila-doctors.com.ph
    usthospital.com.ph
    mmcenters.com
    vrp.com.ph
    worldciti.com.ph
    capitolmedical.com.ph
    maryjohnstonhospital.com
    unihealthsystem.com.ph
    dlshsi.edu.ph
    eastave.org
    lcp.gov.ph
    nkti.gov.ph
    pcmc.gov.ph
    jrrmmc.gov.ph
    osmaktmc.com
    southcityhospitals.com
    acehospital.com.ph
    healthway.com.ph
    qualimed.com.ph
    perpetualdalta.edu.ph
    adventisthealthcare.org.ph
    cebudocgroup.com.ph
    chonghua.com.ph
    davaodoctors.com.ph
    spmc.doh.gov.ph
    corazonlocsinhospital.org
    afeccglobal.com
    featiuniversityhospital.com
    iloilodoctorshospital.com
    r1mc.doh.gov.ph
    evrmc.doh.gov.ph
    cvmc.doh.gov.ph
    bghmc.doh.gov.ph
    up.edu.ph
    ateneo.edu
    dlsu.edu.ph
    ust.edu.ph
    feu.edu.ph
    mapua.edu.ph
    adamson.edu.ph
    ue.edu.ph
    ceu.edu.ph
    tip.edu.ph
    pup.edu.ph
    plm.edu.ph
    nu.edu.ph
    sanbeda.edu.ph
    arellano.edu.ph
    lyceum.edu.ph
    iacademy.edu.ph
    apc.edu.ph
    ciit.edu.ph
    benilde.edu.ph
    adu.edu.ph
    slu.edu.ph
    silliman.edu.ph
    usc.edu.ph
    usjr.edu.ph
    xu.edu.ph
    msuiit.edu.ph
    mindanao.edu.ph
    batstate-u.edu.ph
    cvsu.edu.ph
    bulsu.edu.ph
    psu.edu.ph
    wvsu.edu.ph
    neu.edu.ph
    amaes.edu.ph
    sti.edu
    informatics.edu.ph
    phinmaed.com
    perpetualdalta.edu.ph
    jru.edu
    eac.edu.ph
    hau.edu.ph
    neu.edu.ph
    olfu.edu.ph
    neu.edu.ph
    tup.edu.ph
    rtu.edu.ph
    pnc.edu.ph
    plmun.edu.ph
    ayala.com
    sminvestments.com
    jgsummit.com.ph
    sanmiguel.com.ph
    aboitiz.com
    megaworldcorp.com
    filinvestgroup.com
    robinsonsland.com
    dmciholdings.com
    vistaresidences.com.ph
    century-properties.com
    bdo.com.ph
    bpi.com.ph
    metrobank.com.ph
    unionbankph.com
    maya.ph
    gcash.com
    globe.com.ph
    smart.com.ph
    pldt.com
    convergeict.com
    dito.ph
    coca-cola.com/ph/en
    nestle.com.ph
    unilever.com.ph
    jollibeegroup.com
    chowking.ph
    greenwich.com.ph
    manginasal.ph
    redribbonbakeshop.com.ph
    maxschicken.com
    shakeyspizza.ph
    potatocorner.com
    frankies.com.ph
    meralco.com.ph
    petron.com
    seaoil.com.ph
    phoenixfuels.ph
    cebuair.com
    philippineairlines.com
    airasia.com
    grab.com/ph
    foodpanda.ph
    lazada.com.ph
    shopee.ph
    carousell.ph
    sprout.ph
    kalibrr.com
    kumu.ph
    paymongo.com
    dragonpay.ph
    coins.ph
    pdax.ph
    uniondigitalbank.io
    gcash.com/gcrypto
    voyagerinnovation.com
    xurpas.com
    exist.com
    pointwest.com.ph
    yondu.com
    stratpoint.com
    orangeandbronze.com
    arcanys.com
    cambridge.org
    kmc.solutions
    gov.ph
    op-proper.gov.ph
    ovp.gov.ph
    senate.gov.ph
    congress.gov.ph
    sc.judiciary.gov.ph
    ca.judiciary.gov.ph
    sb.judiciary.gov.ph
    dbm.gov.ph
    dof.gov.ph
    dti.gov.ph
    dict.gov.ph
    dost.gov.ph
    deped.gov.ph
    ched.gov.ph
    tesda.gov.ph
    dole.gov.ph
    dfa.gov.ph
    immigration.gov.ph
    nbi.gov.ph
    pnp.gov.ph
    bfp.gov.ph
    bjmp.gov.ph
    napolcom.gov.ph
    dswd.gov.ph
    philhealth.gov.ph
    sss.gov.ph
    pagibigfund.gov.ph
    bir.gov.ph
    boi.gov.ph
    peza.gov.ph
    sec.gov.ph
    ltfrb.gov.ph
    lto.gov.ph
    marina.gov.ph
    caap.gov.ph
    dotr.gov.ph
    dpwh.gov.ph
    denr.gov.ph
    pagasa.dost.gov.ph
    phivolcs.dost.gov.ph
    da.gov.ph
    bfar.da.gov.ph
    neda.gov.ph
    psa.gov.ph
    comelec.gov.ph
    csc.gov.ph
    coa.gov.ph
    ombudsman.gov.ph
    dilg.gov.ph
    doh.gov.ph
    tourism.gov.ph
    pcso.gov.ph
    landbank.com
    dbp.ph
    bsp.gov.ph
    customs.gov.ph
    tariffcommission.gov.ph
    ipophil.gov.ph
    cdrrmo.gov.ph
    e.gov.ph
    open.gov.ph
    officialgazette.gov.ph
)

TOTAL=${#DOMAINS[@]}
RESULTS="["
SEP=""
PASSED=0
FAILED=0
ERRORS=0

echo ""
echo "RonwayScanner Bulk Scan — $TOTAL targets"
echo "API: $API_BASE"
echo "Output: $OUT_FILE"
echo "------------------------------------------------------------"

for i in "${!DOMAINS[@]}"; do
    DOMAIN="${DOMAINS[$i]}"
    NUM=$((i + 1))
    printf "[%d/%d] %-45s " "$NUM" "$TOTAL" "$DOMAIN"

    RESPONSE=$(curl -s --max-time 30 -X POST "$API_BASE/api/scan" \
        -H "Content-Type: application/json" \
        -d "{\"target\": \"$DOMAIN\"}" 2>/dev/null) || true

    if [ -z "$RESPONSE" ] || ! echo "$RESPONSE" | jq -e . >/dev/null 2>&1; then
        echo "ERROR: no response or invalid JSON"
        RESULTS+="${SEP}{\"domain\":\"$DOMAIN\",\"risk_level\":\"error\",\"risk_score\":null,\"harvest_risk\":false}"
        ERRORS=$((ERRORS + 1))
    else
        SCORE=$(echo "$RESPONSE"   | jq -r '.risk_score.value   // "?"')
        LEVEL=$(echo "$RESPONSE"   | jq -r '.risk_score.level   // "unknown"')
        HARVEST=$(echo "$RESPONSE" | jq -r '.risk_score.harvest_risk // false')

        HARVEST_TAG=""
        [ "$HARVEST" = "true" ] && HARVEST_TAG=" [HARVEST RISK]"

        printf "%s (%s)%s\n" "$LEVEL" "$SCORE" "$HARVEST_TAG"

        RESULTS+="${SEP}$(echo "$RESPONSE" | jq -c \
            '{domain: .target.domain, risk_score: .risk_score.value, risk_level: .risk_score.level, harvest_risk: .risk_score.harvest_risk, quantum_ready: .quantum_ready, tls_version: .tls.version}')"

        [ "$LEVEL" = "Pass" ] && PASSED=$((PASSED + 1)) || FAILED=$((FAILED + 1))
    fi

    SEP=","

    if [ "$NUM" -lt "$TOTAL" ]; then
        sleep "$DELAY"
    fi
done

RESULTS+="]"

echo ""
echo "============================================================"
echo "SCAN COMPLETE"
echo "  Total   : $TOTAL"
echo "  Passed  : $PASSED"
echo "  At Risk : $FAILED"
echo "  Errors  : $ERRORS"
echo ""
echo "Top 10 riskiest:"
echo "$RESULTS" | jq -r 'map(select(.risk_score != null)) | sort_by(-.risk_score) | .[0:10][] | "  \(.domain)  \(.risk_score)  \(.risk_level)"'

echo "$RESULTS" | jq '.' > "$OUT_FILE"
echo ""
echo "Full results saved to: $OUT_FILE"
