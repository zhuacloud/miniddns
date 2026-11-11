/* ca.c — §09 PEM bundle -> BearSSL trust anchors, two-stage arena */
#include "ca.h"
#include "log.h"
#include "util.h"

#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* BearSSL dates are days since 0000-01-01; mn_ca_info uses Unix-epoch days. */
#define MN_CA_DAYS_TO_EPOCH  719528u
#define MN_CA_BLOB_LIMIT     ((size_t)MN_LIMIT_CA_FILE * 2u)

static void ca_copy_literal(char *dst, size_t cap, const char *src)
{
    size_t n;

    if (cap == 0) {
        return;
    }
    n = strlen(src);
    if (n >= cap) {
        n = cap - 1;
    }
    if (n > 0) {
        memcpy(dst, src, n);
    }
    dst[n] = '\0';
}

static void ca_set_err(char *err, size_t errlen, const char *fmt, ...)
{
    va_list ap;
    int r;

    if (err == NULL || errlen == 0) {
        return;
    }
    va_start(ap, fmt);
    r = vsnprintf(err, errlen, fmt, ap);
    va_end(ap);
    if (r < 0) {
        err[0] = '\0';
    }
}

/* Howard Hinnant's civil_from_days, with days counted from 1970-01-01. */
static int ca_format_date(uint32_t days, char *out, size_t cap)
{
    int64_t z, era, doe, yoe, y, doy, mp, d, m;
    int r;

    if (cap == 0) {
        return -1;
    }
    z = (int64_t)days + 719468;
    era = (z >= 0 ? z : z - 146096) / 146097;
    doe = z - era * 146097;
    yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    y = yoe + era * 400;
    doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    mp = (5 * doy + 2) / 153;
    d = doy - (153 * mp + 2) / 5 + 1;
    m = mp + (mp < 10 ? 3 : -9);
    y += (m <= 2);
    r = snprintf(out, cap, "%04lld-%02lld-%02lld",
                 (long long)y, (long long)m, (long long)d);
    if (r < 0 || (size_t)r >= cap) {
        ca_copy_literal(out, cap, "1970-01-01");
        return -1;
    }
    return 0;
}

static void ca_log_value(const char *in, char *out, size_t cap)
{
    size_t i, o;

    if (cap == 0) {
        return;
    }
    if (in == NULL) {
        out[0] = '\0';
        return;
    }
    for (i = 0, o = 0; in[i] != '\0' && o + 1 < cap; i++) {
        unsigned char c = (unsigned char)in[i];

        if (c < 0x20 || c > 0x7e || c == '"' || c == '\\') {
            c = '_';
        }
        out[o++] = (char)c;
    }
    out[o] = '\0';
}

/* Best-effort CN extraction from DER-encoded X.500 name bytes. */
static void ca_extract_cn(const unsigned char *dn, size_t len,
                          char *out, size_t cap)
{
    size_t i, p, nlen, k, o;
    int tag;

    if (cap == 0) {
        return;
    }
    out[0] = '\0';
    if (dn == NULL || len < 6) {
        ca_copy_literal(out, cap, "CN=unknown");
        return;
    }
    for (i = 0; i + 5 <= len; i++) {
        if (dn[i] != 0x06 || dn[i + 1] != 0x03 || dn[i + 2] != 0x55 ||
            dn[i + 3] != 0x04 || dn[i + 4] != 0x03) {
            continue;
        }
        p = i + 5;
        if (p >= len) {
            continue;
        }
        tag = dn[p++];
        if (tag != 0x0c && tag != 0x13 && tag != 0x14 &&
            tag != 0x16 && tag != 0x1a) {
            continue;
        }
        if (p >= len) {
            continue;
        }
        if ((dn[p] & 0x80) == 0) {
            nlen = dn[p++];
        } else {
            size_t nb = (size_t)(dn[p++] & 0x7f);

            if (nb == 0 || nb > sizeof(size_t) || p + nb > len) {
                continue;
            }
            nlen = 0;
            for (k = 0; k < nb; k++) {
                nlen = (nlen << 8) | dn[p++];
            }
        }
        if (nlen > len - p) {
            continue;
        }
        ca_copy_literal(out, cap, "CN=");
        o = strlen(out);
        for (k = 0; k < nlen && o + 1 < cap; k++) {
            unsigned char c = dn[p + k];

            if (c < 0x20 || c > 0x7e || c == '"' || c == '\\') {
                c = '_';
            }
            out[o++] = (char)c;
        }
        out[o] = '\0';
        return;
    }
    ca_copy_literal(out, cap, "CN=unknown");
}

struct ca_vec {
    unsigned char *data;
    size_t len;
    size_t cap;
    size_t max;
    int failed;
};

static int ca_vec_reserve(struct ca_vec *v, size_t need)
{
    size_t ncap;
    unsigned char *p;

    if (need > v->max || need < v->len) {
        v->failed = 1;
        return -1;
    }
    if (need <= v->cap) {
        return 0;
    }
    ncap = v->cap != 0 ? v->cap : 256;
    while (ncap < need) {
        if (ncap > v->max / 2) {
            ncap = v->max;
            break;
        }
        ncap *= 2;
    }
    if (ncap > v->max) {
        ncap = v->max;
    }
    p = (unsigned char *)realloc(v->data, ncap);
    if (p == NULL) {
        v->failed = 1;
        return -1;
    }
    v->data = p;
    v->cap = ncap;
    return 0;
}

static int ca_vec_append(struct ca_vec *v, const void *src, size_t len,
                         size_t *off)
{
    if (len > SIZE_MAX - v->len) {
        v->failed = 1;
        return -1;
    }
    if (ca_vec_reserve(v, v->len + len) < 0) {
        return -1;
    }
    if (off != NULL) {
        *off = v->len;
    }
    if (len > 0) {
        memcpy(v->data + v->len, src, len);
    }
    v->len += len;
    return 0;
}

static void ca_vec_clear(struct ca_vec *v)
{
    free(v->data);
    memset(v, 0, sizeof *v);
}

/*
 * Collection records contain offsets only: the blob vector and this array may
 * both be realloc()ed before the final arena is allocated.
 */
struct ca_rec {
    size_t dn_off, dn_len;
    size_t n_off, n_len;
    size_t e_off, e_len;
    size_t q_off, q_len;
    unsigned char key_type;
    unsigned flags;
    int curve;
    uint32_t notafter_days;
    uint32_t notafter_seconds;
    uint32_t expiry_days;
    int time_valid;
};

struct ca_recs {
    struct ca_rec *data;
    size_t len;
    size_t cap;
    int failed;
};

static int ca_recs_append(struct ca_recs *v, const struct ca_rec *rec)
{
    struct ca_rec *p;
    size_t ncap;

    if (v->len >= (size_t)MN_CA_MAX_ANCHORS) {
        v->failed = 1;
        return -1;
    }
    if (v->len == v->cap) {
        ncap = v->cap != 0 ? v->cap * 2 : 32;
        if (ncap > (size_t)MN_CA_MAX_ANCHORS) {
            ncap = (size_t)MN_CA_MAX_ANCHORS;
        }
        p = (struct ca_rec *)realloc(v->data, ncap * sizeof *p);
        if (p == NULL) {
            v->failed = 1;
            return -1;
        }
        v->data = p;
        v->cap = ncap;
    }
    v->data[v->len++] = *rec;
    return 0;
}

static void ca_recs_clear(struct ca_recs *v)
{
    free(v->data);
    memset(v, 0, sizeof *v);
}

struct ca_parse {
    struct ca_vec der;
    struct ca_vec blobs;
    struct ca_recs recs;
    int in_cert;
    int saw_cert;
    int der_oversized;
    int fatal;
    size_t n_total;
    size_t n_skipped;
    size_t n_expired;
    size_t n_truncated;
    int earliest_valid;
    uint32_t earliest_days;
    int64_t earliest_epoch;
    int64_t now_epoch;
    char earliest_subject[128];
    char fatal_msg[192];
};

static void ca_dn_append(void *ctx, const void *buf, size_t len)
{
    struct ca_vec *v = (struct ca_vec *)ctx;

    (void)ca_vec_append(v, buf, len, NULL);
}

static void ca_pem_dest(void *ctx, const void *src, size_t len)
{
    struct ca_parse *st = (struct ca_parse *)ctx;

    if (!st->in_cert || st->fatal || st->der_oversized) {
        return;
    }
    if (len > (size_t)MN_LIMIT_DER - st->der.len) {
        st->der_oversized = 1;
        return;
    }
    if (ca_vec_append(&st->der, src, len, NULL) < 0) {
        st->fatal = 1;
        ca_set_err(st->fatal_msg, sizeof st->fatal_msg,
                   "out of memory while decoding certificate DER");
    }
}

static int ca_process_cert(struct ca_parse *st)
{
    struct ca_vec dn;
    br_x509_decoder_context dc;
    br_x509_pkey *pk;
    struct ca_rec rec;
    size_t der_len, blob_start;
    int oversized, derr;
    uint32_t expiry_days;
    int64_t expiry_epoch;

    der_len = st->der.len;
    oversized = st->der_oversized;
    st->der.len = 0;
    st->der_oversized = 0;
    st->in_cert = 0;

    if (st->fatal) {
        return -1;
    }
    if (oversized || st->der.failed || der_len == 0) {
        st->n_skipped++;
        return 0;
    }
    if (st->recs.len >= (size_t)MN_CA_MAX_ANCHORS) {
        st->n_skipped++;
        if (st->n_truncated++ == 0) {
            mn_log(MN_LOG_WARN, "ca anchors_truncated=%d limit=%zu",
                   MN_CA_MAX_ANCHORS, (size_t)MN_CA_MAX_ANCHORS);
        }
        return 0;
    }

    memset(&dn, 0, sizeof dn);
    dn.max = (size_t)MN_LIMIT_DER;
    br_x509_decoder_init(&dc, ca_dn_append, &dn);
    br_x509_decoder_push(&dc, st->der.data, der_len);
    derr = br_x509_decoder_last_error(&dc);
    pk = br_x509_decoder_get_pkey(&dc);
    if (derr != 0 || pk == NULL || dn.failed || dn.len == 0) {
        ca_vec_clear(&dn);
        st->n_skipped++;
        return 0;
    }
    if (pk->key_type != BR_KEYTYPE_RSA && pk->key_type != BR_KEYTYPE_EC) {
        ca_vec_clear(&dn);
        st->n_skipped++;
        return 0;
    }
    if (pk->key_type == BR_KEYTYPE_RSA) {
        if (pk->key.rsa.n == NULL || pk->key.rsa.e == NULL ||
            pk->key.rsa.nlen == 0 || pk->key.rsa.elen == 0 ||
            pk->key.rsa.nlen > (size_t)MN_LIMIT_DER ||
            pk->key.rsa.elen > (size_t)MN_LIMIT_DER) {
            ca_vec_clear(&dn);
            st->n_skipped++;
            return 0;
        }
    } else if (pk->key.ec.q == NULL || pk->key.ec.qlen == 0 ||
               pk->key.ec.qlen > (size_t)MN_LIMIT_DER ||
               pk->key.ec.q[0] != 0x04) {
        ca_vec_clear(&dn);
        st->n_skipped++;
        return 0;
    }
    if (dc.notafter_days < MN_CA_DAYS_TO_EPOCH ||
        dc.notafter_seconds > 86400u) {
        ca_vec_clear(&dn);
        st->n_skipped++;
        return 0;
    }
    expiry_days = dc.notafter_days - MN_CA_DAYS_TO_EPOCH;
    expiry_epoch = (int64_t)expiry_days * 86400 +
                   (int64_t)dc.notafter_seconds;

    memset(&rec, 0, sizeof rec);
    blob_start = st->blobs.len;
    if (ca_vec_append(&st->blobs, dn.data, dn.len, &rec.dn_off) < 0) {
        goto oom;
    }
    rec.dn_len = dn.len;
    rec.key_type = pk->key_type;
    rec.flags = br_x509_decoder_isCA(&dc) ? BR_X509_TA_CA : 0u;
    rec.notafter_days = dc.notafter_days;
    rec.notafter_seconds = dc.notafter_seconds;
    rec.expiry_days = expiry_days;
    rec.time_valid = 1;
    if (pk->key_type == BR_KEYTYPE_RSA) {
        if (ca_vec_append(&st->blobs, pk->key.rsa.n, pk->key.rsa.nlen,
                          &rec.n_off) < 0) {
            goto oom;
        }
        rec.n_len = pk->key.rsa.nlen;
        if (ca_vec_append(&st->blobs, pk->key.rsa.e, pk->key.rsa.elen,
                          &rec.e_off) < 0) {
            goto oom;
        }
        rec.e_len = pk->key.rsa.elen;
    } else {
        rec.curve = pk->key.ec.curve;
        if (ca_vec_append(&st->blobs, pk->key.ec.q, pk->key.ec.qlen,
                          &rec.q_off) < 0) {
            goto oom;
        }
        rec.q_len = pk->key.ec.qlen;
    }
    if (ca_recs_append(&st->recs, &rec) < 0) {
        goto oom;
    }
    if (expiry_epoch <= st->now_epoch) {
        st->n_expired++;
    }
    if (!st->earliest_valid || expiry_epoch < st->earliest_epoch) {
        st->earliest_valid = 1;
        st->earliest_days = expiry_days;
        st->earliest_epoch = expiry_epoch;
        ca_extract_cn(dn.data, dn.len, st->earliest_subject,
                      sizeof st->earliest_subject);
    }
    ca_vec_clear(&dn);
    return 0;

oom:
    st->blobs.len = blob_start;
    ca_vec_clear(&dn);
    st->fatal = 1;
    ca_set_err(st->fatal_msg, sizeof st->fatal_msg,
               "out of memory while collecting trust anchors");
    return -1;
}

static void ca_parse_clear(struct ca_parse *st)
{
    ca_vec_clear(&st->der);
    ca_vec_clear(&st->blobs);
    ca_recs_clear(&st->recs);
}

static const char *ca_source(const char *path)
{
    if (path == NULL || strncmp(path, "/etc/", 5) == 0 ||
        strcmp(path, "/etc") == 0) {
        return "system";
    }
    return "bundled";
}

int mn_ca_parse_bundle(const char *buf, size_t len,
                       br_x509_trust_anchor **anchors, size_t *n_anchors,
                       void **arena, struct mn_ca_info *info,
                       char *err, size_t errlen)
{
    struct ca_parse st;
    br_pem_decoder_context pc;
    const unsigned char *p;
    size_t left, n, anchor_bytes, total, i;
    unsigned char *blob_base;
    br_x509_trust_anchor *ta;
    int extra_nl, ev, rc;
    void *final_arena;

    if (anchors != NULL) {
        *anchors = NULL;
    }
    if (n_anchors != NULL) {
        *n_anchors = 0;
    }
    if (arena != NULL) {
        *arena = NULL;
    }
    if (info != NULL) {
        memset(info, 0, sizeof *info);
    }
    if (anchors == NULL || n_anchors == NULL || arena == NULL ||
        buf == NULL || len == 0) {
        ca_set_err(err, errlen, "empty CA bundle");
        return E_CA_LOAD;
    }
    if (len > (size_t)MN_LIMIT_CA_FILE) {
        ca_set_err(err, errlen, "CA bundle too large len=%zu", len);
        return E_CA_LOAD;
    }

    memset(&st, 0, sizeof st);
    st.der.max = (size_t)MN_LIMIT_DER;
    st.blobs.max = MN_CA_BLOB_LIMIT;
    st.earliest_epoch = INT64_MAX;
    st.now_epoch = (int64_t)time(NULL);
    if (st.now_epoch < 0) {
        st.now_epoch = 0;
    }
    ca_copy_literal(st.earliest_subject, sizeof st.earliest_subject,
                    "CN=unknown");

    br_pem_decoder_init(&pc);
    p = (const unsigned char *)buf;
    left = len;
    extra_nl = 1;
    rc = 0;
    while (left > 0) {
        size_t used = br_pem_decoder_push(&pc, p, left);

        p += used;
        left -= used;
        ev = br_pem_decoder_event(&pc);
        switch (ev) {
        case BR_PEM_BEGIN_OBJ: {
            const char *name = br_pem_decoder_name(&pc);

            if (st.in_cert) {
                rc = -1;
                ca_set_err(st.fatal_msg, sizeof st.fatal_msg,
                           "unfinished PEM object");
                break;
            }
            if (strcmp(name, "CERTIFICATE") == 0) {
                st.saw_cert = 1;
                st.n_total++;
                st.in_cert = 1;
                st.der.len = 0;
                st.der_oversized = 0;
                br_pem_decoder_setdest(&pc, ca_pem_dest, &st);
            } else {
                br_pem_decoder_setdest(&pc, NULL, NULL);
            }
            break;
        }
        case BR_PEM_END_OBJ:
            if (st.in_cert && ca_process_cert(&st) < 0) {
                rc = -1;
            }
            br_pem_decoder_setdest(&pc, NULL, NULL);
            break;
        case BR_PEM_ERROR:
            rc = -1;
            ca_set_err(st.fatal_msg, sizeof st.fatal_msg,
                       "invalid PEM encoding");
            break;
        default:
            break;
        }
        if (rc < 0 || st.fatal) {
            break;
        }
        if (used == 0 && ev == 0) {
            rc = -1;
            ca_set_err(st.fatal_msg, sizeof st.fatal_msg,
                       "PEM decoder made no progress");
            break;
        }
        /* Reference decode_pem() adds one newline for files lacking a final LF. */
        if (left == 0 && extra_nl) {
            extra_nl = 0;
            p = (const unsigned char *)"\n";
            left = 1;
        }
    }
    if (rc == 0 && st.in_cert) {
        rc = -1;
        ca_set_err(st.fatal_msg, sizeof st.fatal_msg,
                   "unfinished PEM object");
    }
    if (rc < 0 || st.fatal) {
        ca_set_err(err, errlen, "%s", st.fatal_msg[0] != '\0' ?
                   st.fatal_msg : "invalid PEM bundle");
        ca_parse_clear(&st);
        return E_CA_LOAD;
    }
    if (!st.saw_cert || st.n_total == 0) {
        ca_set_err(err, errlen, "no PEM CERTIFICATE objects");
        ca_parse_clear(&st);
        return E_CA_LOAD;
    }
    if (st.recs.len == 0) {
        ca_set_err(err, errlen,
                   "no usable trust anchors skipped=%zu", st.n_skipped);
        ca_parse_clear(&st);
        return E_CA_LOAD;
    }

    n = st.recs.len;
    anchor_bytes = n * sizeof(br_x509_trust_anchor);
    if (st.blobs.len > SIZE_MAX - anchor_bytes) {
        ca_set_err(err, errlen, "trust anchor arena too large");
        ca_parse_clear(&st);
        return E_CA_LOAD;
    }
    total = anchor_bytes + st.blobs.len;
    final_arena = malloc(total != 0 ? total : 1);
    if (final_arena == NULL) {
        ca_set_err(err, errlen, "out of memory allocating trust anchor arena");
        ca_parse_clear(&st);
        return E_CA_LOAD;
    }
    ta = (br_x509_trust_anchor *)final_arena;
    blob_base = (unsigned char *)final_arena + anchor_bytes;
    if (st.blobs.len > 0) {
        memcpy(blob_base, st.blobs.data, st.blobs.len);
    }
    /* Pointers are installed only after the single final allocation exists. */
    for (i = 0; i < n; i++) {
        const struct ca_rec *rec = &st.recs.data[i];

        memset(&ta[i], 0, sizeof ta[i]);
        ta[i].dn.data = blob_base + rec->dn_off;
        ta[i].dn.len = rec->dn_len;
        ta[i].flags = rec->flags;
        ta[i].pkey.key_type = rec->key_type;
        if (rec->key_type == BR_KEYTYPE_RSA) {
            ta[i].pkey.key.rsa.n = blob_base + rec->n_off;
            ta[i].pkey.key.rsa.nlen = rec->n_len;
            ta[i].pkey.key.rsa.e = blob_base + rec->e_off;
            ta[i].pkey.key.rsa.elen = rec->e_len;
        } else {
            ta[i].pkey.key.ec.curve = rec->curve;
            ta[i].pkey.key.ec.q = blob_base + rec->q_off;
            ta[i].pkey.key.ec.qlen = rec->q_len;
        }
    }

    *anchors = ta;
    *n_anchors = n;
    *arena = final_arena;
    if (info != NULL) {
        memset(info, 0, sizeof *info);
        info->n_total = st.n_total;
        info->n_skipped = st.n_skipped;
        info->n_expired = st.n_expired;
        info->earliest_days = st.earliest_days;
        info->earliest_valid = st.earliest_valid;
        ca_copy_literal(info->earliest_subject,
                        sizeof info->earliest_subject,
                        st.earliest_subject);
    }
    ca_set_err(err, errlen, "%s", "");
    ca_parse_clear(&st);
    return MN_OK;
}

static int ca_stat_signature(const char *path, char *resolved, size_t cap,
                             struct stat *sb, char *err, size_t errlen)
{
    char real[PATH_MAX];
    int r;

    if (realpath(path, real) == NULL) {
        ca_set_err(err, errlen, "ca realpath failed path=%s", path);
        return -1;
    }
    if (stat(real, sb) != 0) {
        ca_set_err(err, errlen, "ca stat failed path=%s", real);
        return -1;
    }
    r = snprintf(resolved, cap, "%s", real);
    if (r < 0 || (size_t)r >= cap) {
        ca_set_err(err, errlen, "ca resolved path too long");
        return -1;
    }
    return 0;
}

int mn_ca_init(struct mn_ca *ca, const char *path, int allow_non_root_owner,
               char *err, size_t errlen)
{
    char *buf;
    char date[16], logpath[MN_LOG_FIELD_MAX + 1], subject[MN_LOG_FIELD_MAX + 1];
    br_x509_trust_anchor *anchors;
    void *arena;
    struct mn_ca_info info;
    struct stat sb;
    size_t len, n;
    int64_t now_days, days_left;
    int r;

    if (ca == NULL || path == NULL || path[0] == '\0') {
        ca_set_err(err, errlen, "invalid CA path");
        return E_CA_LOAD;
    }
    memset(ca, 0, sizeof *ca);
    ca->allow_non_root_owner = allow_non_root_owner;
    ca_set_err(err, errlen, "%s", "");
    buf = (char *)malloc((size_t)MN_LIMIT_CA_FILE);
    if (buf == NULL) {
        ca_set_err(err, errlen, "out of memory reading CA bundle");
        return E_CA_LOAD;
    }
    len = 0;
    if (mn_checked_read(path, MN_FILE_CA, buf, (size_t)MN_LIMIT_CA_FILE,
                        &len, allow_non_root_owner, err, errlen) != 0) {
        if (err != NULL && errlen > 0 && err[0] == '\0') {
            ca_set_err(err, errlen, "ca checked_read failed path=%s", path);
        }
        free(buf);
        return E_CA_LOAD;
    }
    anchors = NULL;
    arena = NULL;
    n = 0;
    memset(&info, 0, sizeof info);
    r = mn_ca_parse_bundle(buf, len, &anchors, &n, &arena, &info,
                           err, errlen);
    free(buf);
    if (r != 0) {
        return E_CA_LOAD;
    }
    if (ca_stat_signature(path, ca->path, sizeof ca->path, &sb,
                          err, errlen) != 0) {
        free(arena);
        return E_CA_LOAD;
    }
    ca->anchors = anchors;
    ca->n_anchors = n;
    ca->arena = arena;
    ca->info = info;
    ca->sig.mtime = sb.st_mtime;
    ca->sig.size = sb.st_size;
    ca->sig.ino = sb.st_ino;

    ca_format_date(info.earliest_days, date, sizeof date);
    ca_log_value(ca->path, logpath, sizeof logpath);
    mn_log(MN_LOG_INFO,
           "ca loaded anchors=%zu path=%s earliest_notAfter=%s source=%s",
           n, logpath, date, ca_source(ca->path));
    if (info.earliest_valid) {
        now_days = (int64_t)(time(NULL) / 86400);
        days_left = (int64_t)info.earliest_days - now_days;
        if (days_left < 90) {
            ca_log_value(info.earliest_subject, subject, sizeof subject);
            mn_log(MN_LOG_WARN,
                   "ca anchor_expiry_days=%lld subject=\"%s\" expires=%s",
                   (long long)days_left, subject, date);
        }
    }
    if (info.n_expired > 0) {
        mn_log(MN_LOG_ERROR, "ca expired_anchors=%zu path=%s",
               info.n_expired, logpath);
    }
    ca_set_err(err, errlen, "%s", "");
    return MN_OK;
}

static int ca_vanished(const char *path, const char *detail)
{
    if (detail != NULL && (strstr(detail, "ENOENT") != NULL ||
                           strstr(detail, "No such file") != NULL)) {
        return 1;
    }
    return access(path, F_OK) != 0 && errno == ENOENT;
}

int mn_ca_refresh(struct mn_ca *ca)
{
    char real[PATH_MAX], detail[256], logpath[MN_LOG_FIELD_MAX + 1];
    char *buf;
    br_x509_trust_anchor *anchors;
    void *arena, *old_arena;
    struct mn_ca_info info;
    struct stat sb;
    size_t len, n, old_n;
    int r;

    if (ca == NULL || ca->path[0] == '\0') {
        return -1;
    }
    if (realpath(ca->path, real) == NULL) {
        return -1;
    }
    if (stat(real, &sb) != 0) {
        if (errno == ENOENT) {
            return -1;
        }
        ca_log_value(ca->path, logpath, sizeof logpath);
        mn_log(MN_LOG_ERROR,
               "ca reload_failed keep_old_anchors=%zu path=%s err=E_CA_LOAD",
               ca->n_anchors, logpath);
        return 0;
    }
    if (sb.st_mtime == ca->sig.mtime && sb.st_size == ca->sig.size &&
        sb.st_ino == ca->sig.ino) {
        return 0;
    }
    ca_log_value(ca->path, logpath, sizeof logpath);
    buf = (char *)malloc((size_t)MN_LIMIT_CA_FILE);
    if (buf == NULL) {
        mn_log(MN_LOG_ERROR,
               "ca reload_failed keep_old_anchors=%zu path=%s err=E_CA_LOAD",
               ca->n_anchors, logpath);
        return 0;
    }
    len = 0;
    detail[0] = '\0';
    r = mn_checked_read(ca->path, MN_FILE_CA, buf,
                        (size_t)MN_LIMIT_CA_FILE, &len,
                        ca->allow_non_root_owner, detail, sizeof detail);
    if (r != 0) {
        free(buf);
        if (ca_vanished(ca->path, detail)) {
            return -1;
        }
        mn_log(MN_LOG_ERROR,
               "ca reload_failed keep_old_anchors=%zu path=%s err=E_CA_LOAD",
               ca->n_anchors, logpath);
        return 0;
    }
    anchors = NULL;
    arena = NULL;
    n = 0;
    memset(&info, 0, sizeof info);
    r = mn_ca_parse_bundle(buf, len, &anchors, &n, &arena, &info,
                           detail, sizeof detail);
    free(buf);
    if (r != 0) {
        if (ca_vanished(ca->path, detail)) {
            return -1;
        }
        mn_log(MN_LOG_ERROR,
               "ca reload_failed keep_old_anchors=%zu path=%s err=E_CA_LOAD",
               ca->n_anchors, logpath);
        return 0;
    }
    old_arena = ca->arena;
    old_n = ca->n_anchors;
    ca->arena = arena;
    ca->anchors = anchors;
    ca->n_anchors = n;
    ca->info = info;
    ca->sig.mtime = sb.st_mtime;
    ca->sig.size = sb.st_size;
    ca->sig.ino = sb.st_ino;
    free(old_arena);
    if (n * 2 < old_n) {
        mn_log(MN_LOG_WARN, "ca_anchor_drop old=%zu new=%zu", old_n, n);
    }
    return 0;
}

const br_x509_trust_anchor *mn_ca_current(struct mn_ca *ca, size_t *n)
{
    if (n != NULL) {
        *n = 0;
    }
    if (ca == NULL) {
        return NULL;
    }
    if (n != NULL) {
        *n = ca->n_anchors;
    }
    return ca->anchors;
}

void mn_ca_free(struct mn_ca *ca)
{
    if (ca == NULL) {
        return;
    }
    free(ca->arena);
    ca->arena = NULL;
    ca->anchors = NULL;
    ca->n_anchors = 0;
}
