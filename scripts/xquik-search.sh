#!/bin/sh

set -eu

usage() {
  printf 'Usage: XQUIK_API_KEY=... %s <query> [output.jsonl] [max-pages]\n' "$0" >&2
}

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

if [ "$#" -lt 1 ] || [ "$#" -gt 3 ]; then
  usage
  exit 2
fi

xq_query=$1
xq_output=${2:-xquik-search.jsonl}
xq_max_pages=${3:-5}
xq_api_key=${XQUIK_API_KEY:-}

[ -n "$xq_query" ] || fail 'Query required. Pass an X search query.'
[ -n "$xq_api_key" ] || fail 'XQUIK_API_KEY required. Export it before running the script.'

case "$xq_api_key" in
  *[!A-Za-z0-9._-]*) fail 'XQUIK_API_KEY contains unsupported characters.' ;;
esac

case "$xq_max_pages" in
  ''|*[!0-9]*) fail 'max-pages must be an integer from 1 through 20.' ;;
esac

if [ "$xq_max_pages" -lt 1 ] || [ "$xq_max_pages" -gt 20 ]; then
  fail 'max-pages must be an integer from 1 through 20.'
fi

for xq_command in curl jq mktemp; do
  command -v "$xq_command" >/dev/null 2>&1 || fail "$xq_command required. Install it first."
done

[ ! -e "$xq_output" ] || fail "Output exists: $xq_output. Choose a new path."

xq_output_dir=$(dirname "$xq_output")
[ -d "$xq_output_dir" ] || fail "Output directory not found: $xq_output_dir"

xq_output_name=$(basename "$xq_output")
xq_response=$(mktemp "${TMPDIR:-/tmp}/xquik-response.XXXXXX")
xq_output_tmp=$(mktemp "$xq_output_dir/.${xq_output_name}.XXXXXX")

cleanup() {
  [ -z "${xq_response:-}" ] || rm -f "$xq_response"
  [ -z "${xq_output_tmp:-}" ] || rm -f "$xq_output_tmp"
}
trap cleanup EXIT HUP INT TERM

request_page() {
  if [ -n "$xq_cursor" ]; then
    printf 'header = "x-api-key: %s"\n' "$xq_api_key" |
      curl --config - --silent --show-error --get \
        --output "$xq_response" --write-out '%{http_code}' \
        --data-urlencode "q=$xq_query" --data-urlencode 'limit=100' \
        --data-urlencode 'queryType=Latest' --data-urlencode "cursor=$xq_cursor" \
        https://xquik.com/api/v1/x/tweets/search
  else
    printf 'header = "x-api-key: %s"\n' "$xq_api_key" |
      curl --config - --silent --show-error --get \
        --output "$xq_response" --write-out '%{http_code}' \
        --data-urlencode "q=$xq_query" --data-urlencode 'limit=100' \
        --data-urlencode 'queryType=Latest' \
        https://xquik.com/api/v1/x/tweets/search
  fi
}

xq_cursor=''
xq_page=1
xq_total=0

while [ "$xq_page" -le "$xq_max_pages" ]; do
  xq_http_code=$(request_page)
  [ "$xq_http_code" = '200' ] || fail "Xquik request failed with HTTP $xq_http_code."

  jq -e '.tweets | type == "array"' "$xq_response" >/dev/null ||
    fail 'Xquik response did not contain a tweets array.'

  xq_collected_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
  jq -c --arg query "$xq_query" --arg collected_at "$xq_collected_at" \
    '.tweets[] | {query: $query, collected_at: $collected_at, source_url: (.url // null), tweet: .}' \
    "$xq_response" >>"$xq_output_tmp"

  xq_page_count=$(jq '.tweets | length' "$xq_response")
  xq_total=$((xq_total + xq_page_count))
  xq_has_next=$(jq -r '.has_next_page == true' "$xq_response")

  if [ "$xq_has_next" != 'true' ]; then
    break
  fi

  xq_next_cursor=$(jq -r 'if (.next_cursor | type) == "string" then .next_cursor else "" end' "$xq_response")
  [ -n "$xq_next_cursor" ] || fail 'Xquik response reported another page without a cursor.'
  [ "$xq_next_cursor" != "$xq_cursor" ] || fail 'Xquik pagination cursor repeated. Stop and retry later.'

  xq_cursor=$xq_next_cursor
  xq_page=$((xq_page + 1))
done

if [ "$xq_has_next" = 'true' ] && [ "$xq_page" -gt "$xq_max_pages" ]; then
  printf 'Stopped at the %s-page limit. Run a narrower query for complete coverage.\n' \
    "$xq_max_pages" >&2
fi

ln "$xq_output_tmp" "$xq_output" || fail "Output exists: $xq_output. Choose a new path."
rm -f "$xq_output_tmp"
xq_output_tmp=''
printf 'Wrote %s public posts to %s.\n' "$xq_total" "$xq_output"
