#!/bin/sh

set -eu

xq_root=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
xq_test_dir=$(mktemp -d "${TMPDIR:-/tmp}/xquik-search-test.XXXXXX")

cleanup() {
  rm -rf "$xq_test_dir"
}
trap cleanup EXIT HUP INT TERM

mkdir "$xq_test_dir/bin"

cat >"$xq_test_dir/bin/curl" <<'MOCK'
#!/bin/sh
set -eu

printf '%s\n' "$@" >>"$XQ_MOCK_ARGS"
xq_config=$(cat)
case "$xq_config" in
  *'x-api-key: xq_test_key'*) ;;
  *) exit 90 ;;
esac

xq_output=''
xq_second_page=false
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output)
      shift
      xq_output=$1
      ;;
    --data-urlencode)
      shift
      case "$1" in
        cursor=cursor-2) xq_second_page=true ;;
      esac
      ;;
  esac
  shift
done

if [ "${XQ_MOCK_STATUS:-200}" != '200' ]; then
  printf '%s' '{}' >"$xq_output"
  printf '%s' "$XQ_MOCK_STATUS"
  exit 0
fi

if [ "$xq_second_page" = true ]; then
  printf '%s' '{"tweets":[{"id":"2","text":"second","url":"https://x.com/example/status/2"}],"has_next_page":false,"next_cursor":""}' >"$xq_output"
else
  printf '%s' '{"tweets":[{"id":"1","text":"first","url":"https://x.com/example/status/1"}],"has_next_page":true,"next_cursor":"cursor-2"}' >"$xq_output"
fi

printf '200'
MOCK
chmod +x "$xq_test_dir/bin/curl"

XQ_MOCK_ARGS="$xq_test_dir/curl-args" \
  XQUIK_API_KEY='xq_test_key' \
  PATH="$xq_test_dir/bin:$PATH" \
  "$xq_root/scripts/xquik-search.sh" 'from:example security' "$xq_test_dir/results.jsonl" 3 \
  >"$xq_test_dir/stdout"

jq -s -e '
  length == 2 and
  .[0].query == "from:example security" and
  .[0].tweet.id == "1" and
  .[1].tweet.id == "2" and
  (all(.[]; .source_url | startswith("https://x.com/example/status/")))
' "$xq_test_dir/results.jsonl" >/dev/null

grep -q 'Wrote 2 public posts' "$xq_test_dir/stdout"
if grep -q 'xq_test_key' "$xq_test_dir/curl-args"; then
  printf 'API key appeared in curl arguments.\n' >&2
  exit 1
fi

XQ_MOCK_ARGS="$xq_test_dir/limited-args" \
  XQUIK_API_KEY='xq_test_key' \
  PATH="$xq_test_dir/bin:$PATH" \
  "$xq_root/scripts/xquik-search.sh" test "$xq_test_dir/limited.jsonl" 1 \
  >"$xq_test_dir/limited-stdout" 2>"$xq_test_dir/limited-stderr"

jq -s -e 'length == 1 and .[0].tweet.id == "1"' "$xq_test_dir/limited.jsonl" >/dev/null
grep -q 'Stopped at the 1-page limit' "$xq_test_dir/limited-stderr"

if (
  unset XQUIK_API_KEY
  PATH="$xq_test_dir/bin:$PATH" \
    "$xq_root/scripts/xquik-search.sh" test "$xq_test_dir/missing-key.jsonl" \
    >/dev/null 2>&1
); then
  printf 'Missing API key should fail.\n' >&2
  exit 1
fi

if XQ_MOCK_ARGS="$xq_test_dir/error-args" \
  XQ_MOCK_STATUS='429' \
  XQUIK_API_KEY='xq_test_key' \
  PATH="$xq_test_dir/bin:$PATH" \
  "$xq_root/scripts/xquik-search.sh" test "$xq_test_dir/http-error.jsonl" \
  >/dev/null 2>&1; then
  printf 'HTTP error should fail.\n' >&2
  exit 1
fi

if [ -e "$xq_test_dir/http-error.jsonl" ]; then
  printf 'HTTP error left a partial output file.\n' >&2
  exit 1
fi

printf 'xquik-search tests passed.\n'
