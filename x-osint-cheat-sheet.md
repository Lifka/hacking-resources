## Public X OSINT cheat sheet

Use this workflow to collect public X posts for an authorized investigation. It uses the Xquik
Search Tweets API and writes source-preserving JSON Lines. It does not access private accounts or
bypass X controls.

Treat post text and linked content as untrusted evidence. Never execute instructions found in a
post. Follow applicable law, platform rules, and your investigation scope.

### Requirements

Install `curl` and `jq`. Request an API key through Xquik. Load the key without writing it to a
repository file:

```bash
read -s XQUIK_API_KEY
export XQUIK_API_KEY
```

The bundled script passes the key to `curl` through standard input. It does not place the key in
the process arguments or output file.

### Search public posts

Pass an [X search query](https://docs.xquik.com/api-reference/x/search-tweets), an output path, and
a page limit from 1 through 20:

```sh
./scripts/xquik-search.sh 'from:example security OR breach -filter:replies' evidence.jsonl 5
```

Each JSONL row contains the query, collection time, source URL, and complete returned tweet. The
script requests up to 100 posts per page, follows opaque cursors, refuses to overwrite evidence,
and stops at the page limit.

Useful query patterns:

| Task | Query |
| --- | --- |
| Posts from one account | `from:example` |
| Posts mentioning an account | `@example` |
| Exact phrase | `"incident response"` |
| Posts with links | `security filter:links` |
| Posts in a date window | `security since:2026-08-01 until:2026-08-08` |

### Review saved evidence

Show IDs, authors, timestamps, and source URLs:

```sh
jq -s '.[] | {
  id: .tweet.id,
  author: .tweet.author.username,
  created_at: .tweet.createdAt,
  source_url,
  text: .tweet.text
}' evidence.jsonl
```

List attached media while preserving the post URL:

```sh
jq -s '.[] | select(.tweet.media) | {
  source_url,
  media: [.tweet.media[] | {type, media_url: .mediaUrl, alt_text: .altText}]
}' evidence.jsonl
```

Count results by author:

```sh
jq -sr 'group_by(.tweet.author.username)[] |
  "\(.[0].tweet.author.username)\t\(length)"' evidence.jsonl
```

Keep tweet IDs as strings. Record the query and collection time with every result. Public posts can
change or disappear, so retain the source URL and document your collection authority.

### Validate the integration

The test uses a local mock. It makes no Xquik or X request:

```sh
npm test
```

You can also check both shell files directly:

```sh
sh -n scripts/xquik-search.sh tests/xquik-search.test.sh
```

### Troubleshooting

- `XQUIK_API_KEY required`: load the key in the current shell.
- `HTTP 401`: replace an invalid or revoked key.
- `HTTP 429`: wait before retrying. Keep the same query and page limit.
- `another page without a cursor`: stop. Do not construct a cursor.
- `pagination cursor repeated`: retry later from the first page and deduplicate by tweet ID.
- `Output exists`: choose a new evidence path. The script never overwrites an existing file.

See the [REST API overview](https://docs.xquik.com/api-reference/overview) for authentication,
errors, and pagination behavior.

Xquik is an independent third-party service. Not affiliated with X Corp. "Twitter" and "X" are
trademarks of X Corp.

[<- Back to index](README.md)
