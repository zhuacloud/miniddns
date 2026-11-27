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
int mn_ca_format_date(uint32_t days, char *out, size_t cap)
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

static int ca_vec_reserve_init(struct ca_vec *v, size_t need, size_t init_cap, int grow_15x)
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
    ncap = v->cap != 0 ? v->cap : init_cap;
    while (ncap < need) {
        size_t step = grow_15x ? (ncap / 2) : ncap;
        if (step == 0) {
            step = 1;
        }
        if (ncap > v->max - step) {
            ncap = v->max;
            break;
        }
        ncap += step;
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

static int ca_vec_append_opts(struct ca_vec *v, const void *src, size_t len,
                              size_t *off, size_t init_cap, int grow_15x)
{
    if (len > SIZE_MAX - v->len) {
        v->failed = 1;
        return -1;
    }
    if (ca_vec_reserve_init(v, v->len + len, init_cap, grow_15x) < 0) {
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

static int ca_vec_append(struct ca_vec *v, const void *src, size_t len,
                         size_t *off)
{
    return ca_vec_append_opts(v, src, len, off, 256, 0);
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
    struct ca_vec dn;
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

    st->dn.len = 0;
    st->dn.failed = 0;
    br_x509_decoder_init(&dc, ca_dn_append, &st->dn);
    br_x509_decoder_push(&dc, st->der.data, der_len);
    derr = br_x509_decoder_last_error(&dc);
    pk = br_x509_decoder_get_pkey(&dc);
    if (derr != 0 || pk == NULL || st->dn.failed || st->dn.len == 0) {
        st->n_skipped++;
        return 0;
    }
    if (pk->key_type != BR_KEYTYPE_RSA && pk->key_type != BR_KEYTYPE_EC) {
        st->n_skipped++;
        return 0;
    }
    if (pk->key_type == BR_KEYTYPE_RSA) {
        if (pk->key.rsa.n == NULL || pk->key.rsa.e == NULL ||
            pk->key.rsa.nlen == 0 || pk->key.rsa.elen == 0 ||
            pk->key.rsa.nlen > (size_t)MN_LIMIT_DER ||
            pk->key.rsa.elen > (size_t)MN_LIMIT_DER) {
            st->n_skipped++;
            return 0;
        }
    } else if (pk->key.ec.q == NULL || pk->key.ec.qlen == 0 ||
               pk->key.ec.qlen > (size_t)MN_LIMIT_DER ||
               pk->key.ec.q[0] != 0x04) {
        st->n_skipped++;
        return 0;
    }
    if (dc.notafter_days < MN_CA_DAYS_TO_EPOCH ||
        dc.notafter_seconds > 86400u) {
        st->n_skipped++;
        return 0;
    }
    expiry_days = dc.notafter_days - MN_CA_DAYS_TO_EPOCH;
    expiry_epoch = (int64_t)expiry_days * 86400 +
                   (int64_t)dc.notafter_seconds;

    memset(&rec, 0, sizeof rec);
    blob_start = st->blobs.len;
    if (ca_vec_append_opts(&st->blobs, st->dn.data, st->dn.len, &rec.dn_off,
                           16384, 1) < 0) {
        goto oom;
    }
    rec.dn_len = st->dn.len;
    rec.key_type = pk->key_type;
    rec.flags = br_x509_decoder_isCA(&dc) ? BR_X509_TA_CA : 0u;
    rec.notafter_days = dc.notafter_days;
    rec.notafter_seconds = dc.notafter_seconds;
    rec.expiry_days = expiry_days;
    rec.time_valid = 1;
    if (pk->key_type == BR_KEYTYPE_RSA) {
        if (ca_vec_append_opts(&st->blobs, pk->key.rsa.n, pk->key.rsa.nlen,
                               &rec.n_off, 16384, 1) < 0) {
            goto oom;
        }
        rec.n_len = pk->key.rsa.nlen;
        if (ca_vec_append_opts(&st->blobs, pk->key.rsa.e, pk->key.rsa.elen,
                               &rec.e_off, 16384, 1) < 0) {
            goto oom;
        }
        rec.e_len = pk->key.rsa.elen;
    } else {
        rec.curve = pk->key.ec.curve;
        if (ca_vec_append_opts(&st->blobs, pk->key.ec.q, pk->key.ec.qlen,
                               &rec.q_off, 16384, 1) < 0) {
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
        ca_extract_cn(st->dn.data, st->dn.len, st->earliest_subject,
                      sizeof st->earliest_subject);
    }
    return 0;

oom:
    st->blobs.len = blob_start;
    st->fatal = 1;
    ca_set_err(st->fatal_msg, sizeof st->fatal_msg,
               "out of memory while collecting trust anchors");
    return -1;
}

static void ca_parse_clear(struct ca_parse *st)
{
    ca_vec_clear(&st->der);
    ca_vec_clear(&st->dn);
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

static void ca_stream_init(struct ca_parse *st, br_pem_decoder_context *pc)
{
    memset(st, 0, sizeof *st);
    st->der.max = (size_t)MN_LIMIT_DER;
    st->dn.max = (size_t)MN_LIMIT_DER;
    st->blobs.max = MN_CA_BLOB_LIMIT;
    st->earliest_epoch = INT64_MAX;
    st->now_epoch = (int64_t)time(NULL);
    if (st->now_epoch < 0) {
        st->now_epoch = 0;
    }
    ca_copy_literal(st->earliest_subject, sizeof st->earliest_subject,
                    "CN=unknown");
    br_pem_decoder_init(pc);
}

static int ca_stream_feed(struct ca_parse *st, br_pem_decoder_context *pc,
                          const unsigned char *p, size_t left)
{
    int ev, rc = 0;

    while (left > 0) {
        size_t used = br_pem_decoder_push(pc, p, left);

        p += used;
        left -= used;
        ev = br_pem_decoder_event(pc);
        switch (ev) {
        case BR_PEM_BEGIN_OBJ: {
            const char *name = br_pem_decoder_name(pc);

            if (st->in_cert) {
                rc = -1;
                ca_set_err(st->fatal_msg, sizeof st->fatal_msg,
                           "unfinished PEM object");
                break;
            }
            if (strcmp(name, "CERTIFICATE") == 0) {
                st->saw_cert = 1;
                st->n_total++;
                st->in_cert = 1;
                st->der.len = 0;
                st->der_oversized = 0;
                br_pem_decoder_setdest(pc, ca_pem_dest, st);
            } else {
                br_pem_decoder_setdest(pc, NULL, NULL);
            }
            break;
        }
        case BR_PEM_END_OBJ:
            if (st->in_cert && ca_process_cert(st) < 0) {
                rc = -1;
            }
            br_pem_decoder_setdest(pc, NULL, NULL);
            break;
        case BR_PEM_ERROR:
            rc = -1;
            ca_set_err(st->fatal_msg, sizeof st->fatal_msg,
                       "invalid PEM encoding");
            break;
        default:
            break;
        }
        if (rc < 0 || st->fatal) {
            return -1;
        }
        if (used == 0 && ev == 0) {
            ca_set_err(st->fatal_msg, sizeof st->fatal_msg,
                       "PEM decoder made no progress");
            return -1;
        }
    }
    return 0;
}

static int ca_stream_finish(struct ca_parse *st, br_pem_decoder_context *pc,
                            br_x509_trust_anchor **anchors, size_t *n_anchors,
                            void **arena, struct mn_ca_info *info,
                            char *err, size_t errlen)
{
    static const unsigned char nl = '\n';
    size_t n, anchor_bytes, total, i;
    unsigned char *blob_base;
    br_x509_trust_anchor *ta;
    void *final_arena;

    /* Reference decode_pem() adds one newline for files lacking a final LF. */
    if (ca_stream_feed(st, pc, &nl, 1) < 0) {
        ca_set_err(err, errlen, "%s", st->fatal_msg[0] != '\0' ?
                   st->fatal_msg : "invalid PEM bundle");
        ca_parse_clear(st);
        return E_CA_LOAD;
    }
    if (st->in_cert) {
        ca_set_err(err, errlen, "unfinished PEM object");
        ca_parse_clear(st);
        return E_CA_LOAD;
    }
    if (st->fatal) {
        ca_set_err(err, errlen, "%s", st->fatal_msg[0] != '\0' ?
                   st->fatal_msg : "invalid PEM bundle");
        ca_parse_clear(st);
        return E_CA_LOAD;
    }
    if (!st->saw_cert || st->n_total == 0) {
        ca_set_err(err, errlen, "no PEM CERTIFICATE objects");
        ca_parse_clear(st);
        return E_CA_LOAD;
    }
    if (st->recs.len == 0) {
        ca_set_err(err, errlen,
                   "no usable trust anchors skipped=%zu", st->n_skipped);
        ca_parse_clear(st);
        return E_CA_LOAD;
    }

    n = st->recs.len;
    anchor_bytes = n * sizeof(br_x509_trust_anchor);
    if (st->blobs.len > SIZE_MAX - anchor_bytes) {
        ca_set_err(err, errlen, "trust anchor arena too large");
        ca_parse_clear(st);
        return E_CA_LOAD;
    }
    total = anchor_bytes + st->blobs.len;
    final_arena = malloc(total != 0 ? total : 1);
    if (final_arena == NULL) {
        ca_set_err(err, errlen, "out of memory allocating trust anchor arena");
        ca_parse_clear(st);
        return E_CA_LOAD;
    }
    ta = (br_x509_trust_anchor *)final_arena;
    blob_base = (unsigned char *)final_arena + anchor_bytes;
    if (st->blobs.len > 0) {
        memcpy(blob_base, st->blobs.data, st->blobs.len);
    }
    /* Pointers are installed only after the single final allocation exists. */
    for (i = 0; i < n; i++) {
        const struct ca_rec *rec = &st->recs.data[i];

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
        info->n_total = st->n_total;
        info->n_skipped = st->n_skipped;
        info->n_expired = st->n_expired;
        info->earliest_days = st->earliest_days;
        info->earliest_valid = st->earliest_valid;
        ca_copy_literal(info->earliest_subject,
                        sizeof info->earliest_subject,
                        st->earliest_subject);
    }
    ca_set_err(err, errlen, "%s", "");
    ca_parse_clear(st);
    return MN_OK;
}

int mn_ca_parse_bundle(const char *buf, size_t len,
                       br_x509_trust_anchor **anchors, size_t *n_anchors,
                       void **arena, struct mn_ca_info *info,
                       char *err, size_t errlen)
{
    struct ca_parse st;
    br_pem_decoder_context pc;

    if (anchors != NULL) *anchors = NULL;
    if (n_anchors != NULL) *n_anchors = 0;
    if (arena != NULL) *arena = NULL;
    if (info != NULL) memset(info, 0, sizeof *info);
    if (anchors == NULL || n_anchors == NULL || arena == NULL ||
        buf == NULL || len == 0) {
        ca_set_err(err, errlen, "empty CA bundle");
        return E_CA_LOAD;
    }
    if (len > (size_t)MN_LIMIT_CA_FILE) {
        ca_set_err(err, errlen, "CA bundle too large len=%zu", len);
        return E_CA_LOAD;
    }
    ca_stream_init(&st, &pc);
    if (ca_stream_feed(&st, &pc, (const unsigned char *)buf, len) < 0) {
        ca_set_err(err, errlen, "%s", st.fatal_msg[0] != '\0' ?
                   st.fatal_msg : "invalid PEM bundle");
        ca_parse_clear(&st);
        return E_CA_LOAD;
    }
    return ca_stream_finish(&st, &pc, anchors, n_anchors, arena, info,
                            err, errlen);
}

/* Stream CA bundle in 4 KiB chunks (v1.3 REQ-02): avoids 2 MiB whole-file malloc
   while enforcing §03 security checks and cumulative <= MN_LIMIT_CA_FILE cap. */
static int ca_load_stream(const char *path, int allow_non_root_owner,
                          char *resolved_out, size_t resolved_cap,
                          struct stat *sb_out,
                          br_x509_trust_anchor **anchors, size_t *n_anchors,
                          void **arena, struct mn_ca_info *info,
                          char *err, size_t errlen)
{
    unsigned char *chunk = NULL;
    struct ca_parse st;
    br_pem_decoder_context pc;
    struct stat sb;
    size_t total = 0;
    int fd;

    *anchors = NULL;
    *n_anchors = 0;
    *arena = NULL;
    memset(info, 0, sizeof *info);
    fd = mn_checked_open(path, MN_FILE_CA, allow_non_root_owner, NULL, &sb,
                         resolved_out, resolved_cap, err, errlen);
    if (fd < 0) {
        if (err != NULL && errlen > 0 && err[0] == '\0') {
            ca_set_err(err, errlen, "ca checked_open failed path=%s", path);
        }
        return E_CA_LOAD;
    }
    chunk = (unsigned char *)malloc(4096);
    if (chunk == NULL) {
        ca_set_err(err, errlen, "out of memory");
        close(fd);
        return E_CA_LOAD;
    }
    ca_stream_init(&st, &pc);
    for (;;) {
        ssize_t r = read(fd, chunk, 4096);
        if (r < 0) {
            if (errno == EINTR) continue;
            ca_set_err(err, errlen, "ca read failed path=%s errno=%d", path, errno);
            free(chunk);
            close(fd);
            ca_parse_clear(&st);
            return E_CA_LOAD;
        }
        if (r == 0) break;
        if ((size_t)r > (size_t)MN_LIMIT_CA_FILE - total) {
            ca_set_err(err, errlen, "ca: file too large path=%s", path);
            free(chunk);
            close(fd);
            ca_parse_clear(&st);
            return E_CA_LOAD;
        }
        total += (size_t)r;
        if (ca_stream_feed(&st, &pc, chunk, (size_t)r) < 0) {
            ca_set_err(err, errlen, "%s", st.fatal_msg[0] != '\0' ?
                       st.fatal_msg : "invalid PEM bundle");
            free(chunk);
            close(fd);
            ca_parse_clear(&st);
            return E_CA_LOAD;
        }
    }
    free(chunk);
    close(fd);
    if (total == 0) {
        ca_set_err(err, errlen, "empty CA bundle");
        ca_parse_clear(&st);
        return E_CA_LOAD;
    }
    if (ca_stream_finish(&st, &pc, anchors, n_anchors, arena, info,
                         err, errlen) != MN_OK) {
        return E_CA_LOAD;
    }
    if (sb_out != NULL) {
        *sb_out = sb;
    }
    return MN_OK;
}

int mn_ca_init(struct mn_ca *ca, const char *path, int allow_non_root_owner,
               char *err, size_t errlen)
{
    char date[16], logpath[MN_LOG_FIELD_MAX + 1], subject[MN_LOG_FIELD_MAX + 1];
    br_x509_trust_anchor *anchors;
    void *arena;
    struct mn_ca_info info;
    struct stat sb;
    size_t n;
    int64_t now_days, days_left;
    int r;

    if (ca == NULL || path == NULL || path[0] == '\0') {
        ca_set_err(err, errlen, "invalid CA path");
        return E_CA_LOAD;
    }
    memset(ca, 0, sizeof *ca);
    ca->allow_non_root_owner = allow_non_root_owner;
    ca_set_err(err, errlen, "%s", "");
    r = ca_load_stream(path, allow_non_root_owner, ca->path, sizeof ca->path,
                       &sb, &anchors, &n, &arena, &info, err, errlen);
    if (r != MN_OK) {
        return E_CA_LOAD;
    }
    ca->anchors = anchors;
    ca->n_anchors = n;
    ca->arena = arena;
    ca->info = info;
    ca->sig.mtime = sb.st_mtime;
    ca->sig.size = sb.st_size;
    ca->sig.ino = sb.st_ino;

    mn_ca_format_date(info.earliest_days, date, sizeof date);
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
    char detail[256], logpath[MN_LOG_FIELD_MAX + 1];
    char *real = NULL;
    br_x509_trust_anchor *anchors;
    void *arena, *old_arena;
    struct mn_ca_info info;
    struct stat sb, loaded_sb;
    size_t n, old_n;
    int r, st_rc, st_err;

    if (ca == NULL || ca->path[0] == '\0') {
        return -1;
    }
    real = realpath(ca->path, NULL);
    if (real == NULL) {
        return -1;
    }
    st_rc = stat(real, &sb);
    st_err = errno;
    free(real);
    if (st_rc != 0) {
        if (st_err == ENOENT) {
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
    detail[0] = '\0';
    r = ca_load_stream(ca->path, ca->allow_non_root_owner, NULL, 0, &loaded_sb,
                       &anchors, &n, &arena, &info, detail, sizeof detail);
    if (r != MN_OK) {
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
    ca->sig.mtime = loaded_sb.st_mtime;
    ca->sig.size = loaded_sb.st_size;
    ca->sig.ino = loaded_sb.st_ino;
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
