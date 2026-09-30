package testdb

import (
	"database/sql"
	"regexp"
	"sort"
	"testing"
)

// catalogSQL prints every object of schema $1 the way pg_dump defines it.
// Columns carry their position among live columns, so column order counts.
const catalogSQL = `
WITH ns AS (SELECT oid FROM pg_namespace WHERE nspname = $1)
SELECT format('relation %s kind=%s persistence=%s options=%s rls=%s acl=%s comment=%s', c.relname, c.relkind, c.relpersistence,
       c.reloptions, c.relrowsecurity, c.relacl, obj_description(c.oid, 'pg_class'))
  FROM pg_class c WHERE c.relnamespace = (SELECT oid FROM ns) AND c.relkind IN ('r','p','v','m','S','f','c')
UNION ALL
SELECT format('column %s.%s %s %s notnull=%s default=%s identity=%s generated=%s collation=%s acl=%s comment=%s',
       c.relname, row_number() OVER (PARTITION BY c.oid ORDER BY a.attnum), a.attname, format_type(a.atttypid, a.atttypmod),
       a.attnotnull, pg_get_expr(d.adbin, d.adrelid), a.attidentity, a.attgenerated, a.attcollation, a.attacl,
       col_description(c.oid, a.attnum))
  FROM pg_attribute a
  JOIN pg_class c ON c.oid = a.attrelid
  LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
 WHERE c.relnamespace = (SELECT oid FROM ns) AND c.relkind IN ('r','p','v','m','f','c') AND a.attnum > 0 AND NOT a.attisdropped
UNION ALL
SELECT format('constraint %s %s %s comment=%s', c.relname, con.conname, pg_get_constraintdef(con.oid), obj_description(con.oid, 'pg_constraint'))
  FROM pg_constraint con LEFT JOIN pg_class c ON c.oid = con.conrelid
 WHERE con.connamespace = (SELECT oid FROM ns)
UNION ALL
SELECT format('index %s comment=%s', pg_get_indexdef(i.indexrelid), obj_description(i.indexrelid, 'pg_class'))
  FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
 WHERE c.relnamespace = (SELECT oid FROM ns)
UNION ALL
SELECT format('trigger %s enabled=%s comment=%s', pg_get_triggerdef(t.oid), t.tgenabled, obj_description(t.oid, 'pg_trigger'))
  FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
 WHERE c.relnamespace = (SELECT oid FROM ns) AND NOT t.tgisinternal
UNION ALL
SELECT format('function %s acl=%s comment=%s', pg_get_functiondef(p.oid), p.proacl, obj_description(p.oid, 'pg_proc'))
  FROM pg_proc p WHERE p.pronamespace = (SELECT oid FROM ns) AND p.prokind IN ('f','p')
UNION ALL
SELECT format('view %s %s', c.relname, pg_get_viewdef(c.oid))
  FROM pg_class c WHERE c.relnamespace = (SELECT oid FROM ns) AND c.relkind IN ('v','m')
UNION ALL
SELECT format('sequence %s %s start=%s increment=%s min=%s max=%s cache=%s cycle=%s', c.relname, format_type(s.seqtypid, NULL),
       s.seqstart, s.seqincrement, s.seqmin, s.seqmax, s.seqcache, s.seqcycle)
  FROM pg_sequence s JOIN pg_class c ON c.oid = s.seqrelid
 WHERE c.relnamespace = (SELECT oid FROM ns)
UNION ALL
SELECT format('type %s %s comment=%s', t.typname, t.typtype, obj_description(t.oid, 'pg_type'))
  FROM pg_type t WHERE t.typnamespace = (SELECT oid FROM ns) AND t.typtype IN ('e','d','r','m')
UNION ALL
SELECT format('policy %s %s', c.relname, pol.polname)
  FROM pg_policy pol JOIN pg_class c ON c.oid = pol.polrelid WHERE c.relnamespace = (SELECT oid FROM ns)
UNION ALL
SELECT format('rule %s', pg_get_ruledef(r.oid))
  FROM pg_rewrite r JOIN pg_class c ON c.oid = r.ev_class
 WHERE c.relnamespace = (SELECT oid FROM ns) AND r.rulename <> '_RETURN'`

// SchemaCatalog lists every object in schema as sorted text: relations and
// their columns in order, types, defaults, constraints, indexes, triggers,
// functions, views, sequences, comments and grants. The schema's own name
// prints as <schema>, so equal catalogs mean identical schemas.
func SchemaCatalog(t testing.TB, db *sql.DB, schema string) []string {
	t.Helper()
	rows, err := db.QueryContext(t.Context(), catalogSQL, schema)
	if err != nil {
		t.Fatalf("read catalog of %s: %v", schema, err)
	}
	defer rows.Close()
	own := regexp.MustCompile(`\b` + regexp.QuoteMeta(schema) + `\b`)
	var out []string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		out = append(out, own.ReplaceAllString(line, "<schema>"))
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return out
}

// CatalogDiff lists lines only in a ("- ") or only in b ("+ ").
func CatalogDiff(a, b []string) []string {
	count := map[string]int{}
	for _, l := range a {
		count[l]++
	}
	for _, l := range b {
		count[l]--
	}
	var out []string
	for _, l := range a {
		if count[l] > 0 {
			count[l]--
			out = append(out, "- "+l)
		}
	}
	for _, l := range b {
		if count[l] < 0 {
			count[l]++
			out = append(out, "+ "+l)
		}
	}
	return out
}
