package flowhawk

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/trace"
)

// SQL comment tags (sqlcommenter format) for query insights: the flow, step and service that sent a query,
// and the traceparent on sampled traces only, appended as a trailing comment. Same as the Node and Python
// SDKs. The Flowhawk collector reads them from pg_stat_activity, so database load and lock waits split by
// flow. Go has no driver hook that may change the SQL, so queries are tagged with TagSQL:
//
//	rows, err := db.QueryContext(ctx, flowhawk.TagSQL(ctx, "SELECT ..."), args...)

type sqlCommentState struct {
	on      bool
	service string
}

var sqlComments atomic.Pointer[sqlCommentState]

// SetSQLComments turns the tags on or off and sets the service name they carry (Init does this).
func SetSQLComments(on bool, service string) {
	sqlComments.Store(&sqlCommentState{on, service})
}

var (
	reTagged   = regexp.MustCompile(`/\*[^*]*='[^*]*\*/\s*;?\s*$`)
	reTrailing = regexp.MustCompile(`\s*;\s*$`)
)

// encodeURIComponent as JavaScript does it, then single quotes escaped (sqlcommenter).
func sqlEnc(v string) string {
	var b strings.Builder
	for _, c := range []byte(v) {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', strings.IndexByte("-_.!~*'()", c) >= 0:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return strings.ReplaceAll(b.String(), "'", `\'`)
}

// SQLComment is the comment for ctx, e.g. /*flow='checkout',service='api',step='pay'*/, or "" outside a
// flow and trace.
func SQLComment(ctx context.Context) string {
	st := sqlComments.Load()
	service := ""
	if st != nil {
		service = st.service
	}
	fs, inFlow := FlowOf(ctx)
	var tags []string
	if inFlow {
		tags = append(tags, "flow='"+sqlEnc(fs.Flow)+"'")
	}
	if service != "" {
		tags = append(tags, "service='"+sqlEnc(service)+"'")
	}
	if inFlow {
		tags = append(tags, "step='"+sqlEnc(fs.Step)+"'")
	}
	sc := trace.SpanContextFromContext(ctx)
	if sc.IsValid() && TraceHash(sc.TraceID()) < current().RateFor(fs.Flow, time.Now()) {
		tags = append(tags, fmt.Sprintf("traceparent='00-%s-%s-%02x'", sc.TraceID(), sc.SpanID(), byte(sc.TraceFlags())&1))
	}
	if !inFlow && len(tags) < 2 {
		return "" // only the service name: not worth changing the query text
	}
	return "/*" + strings.Join(tags, ",") + "*/"
}

// TagSQL appends the comment tags to a query, before a trailing semicolon. A query that already has tags,
// or tags turned off (FLOWHAWK_SQL_COMMENTS=off), leaves the query as it is.
func TagSQL(ctx context.Context, sql string) string {
	if st := sqlComments.Load(); st != nil && !st.on || reTagged.MatchString(sql) {
		return sql
	}
	c := SQLComment(ctx)
	if c == "" {
		return sql
	}
	if loc := reTrailing.FindStringIndex(sql); loc != nil {
		return sql[:loc[0]] + " " + c + ";"
	}
	return sql + " " + c
}
