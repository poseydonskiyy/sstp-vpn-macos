/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef SSTP_MACOS_TRUST_H
#define SSTP_MACOS_TRUST_H

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

static int sstp_append_certificate(CFMutableArrayRef target, X509 *source)
{
    unsigned char *der = NULL;
    int size = source ? i2d_X509(source, &der) : 0;
    if (size <= 0)
        return 0;

    CFDataRef data = CFDataCreate(kCFAllocatorDefault, der, size);
    OPENSSL_free(der);
    if (!data)
        return 0;

    SecCertificateRef certificate = SecCertificateCreateWithData(kCFAllocatorDefault, data);
    CFRelease(data);
    if (!certificate)
        return 0;

    CFArrayAppendValue(target, certificate);
    CFRelease(certificate);
    return 1;
}

static int sstp_is_root_ca(X509 *certificate)
{
    return X509_check_ca(certificate) > 0 &&
           X509_check_issued(certificate, certificate) == X509_V_OK &&
           X509_verify(certificate, X509_get0_pubkey(certificate)) == 1;
}

static int sstp_load_private_ca(const char *path, CFMutableArrayRef chain, CFMutableArrayRef roots)
{
    BIO *file = BIO_new_file(path, "rb");
    if (!file)
        return 0;

    STACK_OF(X509_INFO) *entries = PEM_X509_INFO_read_bio(file, NULL, NULL, NULL);
    BIO_free(file);
    if (!entries)
        return 0;

    int valid = 1;
    for (int index = 0; index < sk_X509_INFO_num(entries); ++index)
    {
        X509_INFO *entry = sk_X509_INFO_value(entries, index);
        if (!entry->x509 || entry->x_pkey || entry->crl || X509_check_ca(entry->x509) <= 0)
        {
            valid = 0;
            break;
        }
        CFMutableArrayRef dest = sstp_is_root_ca(entry->x509) ? roots : chain;
        if (!sstp_append_certificate(dest, entry->x509))
        {
            valid = 0;
            break;
        }
    }

    sk_X509_INFO_pop_free(entries, X509_INFO_free);
    return valid && CFArrayGetCount(roots) > 0;
}

static int sstp_macos_verify_peer(X509_STORE_CTX *context, void *argument)
{
    const sstp_option_st *options = argument;
    const char *hostname = options->host ? options->host : options->server;
    CFStringRef name = CFStringCreateWithCString(kCFAllocatorDefault, hostname, kCFStringEncodingUTF8);
    CFMutableArrayRef chain = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
    CFMutableArrayRef roots = NULL;
    SecPolicyRef policy = NULL;
    SecTrustRef trust = NULL;
    CFErrorRef error = NULL;
    int valid = 0;

    X509 *leaf = X509_STORE_CTX_get0_cert(context);
    STACK_OF(X509) *peers = X509_STORE_CTX_get0_untrusted(context);
    X509_STORE_CTX_set_error(context, X509_V_ERR_APPLICATION_VERIFICATION);

    if (!name || !chain || sk_X509_num(peers) > 32 || !sstp_append_certificate(chain, leaf))
        goto done;

    for (int index = 0; index < sk_X509_num(peers); ++index)
    {
        X509 *peer = sk_X509_value(peers, index);
        if (X509_cmp(leaf, peer) != 0 && !sstp_append_certificate(chain, peer))
            goto done;
    }

    if (options->ca_cert)
    {
        roots = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
        if (!roots || !sstp_load_private_ca(options->ca_cert, chain, roots))
        {
            log_err("The custom bundle must contain a self-signed root CA and optional intermediate CAs");
            goto done;
        }
    }

    policy = SecPolicyCreateSSL(true, name);
    if (!policy || SecTrustCreateWithCertificates(chain, policy, &trust) != errSecSuccess)
        goto done;

    if (roots &&
        (SecTrustSetAnchorCertificates(trust, roots) != errSecSuccess ||
         SecTrustSetAnchorCertificatesOnly(trust, true) != errSecSuccess))
        goto done;

    if (!SecTrustEvaluateWithError(trust, &error))
        goto done;

    X509_STORE_CTX_set_error(context, X509_V_OK);
    valid = 1;

done:
    if (!valid)
    {
        char reason[1024] = "";
        CFStringRef description = error ? CFErrorCopyDescription(error) : NULL;
        if (description)
        {
            CFStringGetCString(description, reason, sizeof(reason), kCFStringEncodingUTF8);
            CFRelease(description);
        }
        log_err("macOS rejected the TLS certificate for %s%s%s",
                hostname, reason[0] ? ": " : "", reason);
    }

    if (error) CFRelease(error);
    if (trust) CFRelease(trust);
    if (policy) CFRelease(policy);
    if (roots) CFRelease(roots);
    if (chain) CFRelease(chain);
    if (name) CFRelease(name);
    return valid;
}

static void sstp_macos_log_tls(const SSL *ssl, int where, int result)
{
    (void)result;
    if (where & SSL_CB_HANDSHAKE_START)
        log_info("TLS handshake started");
    if (where & SSL_CB_HANDSHAKE_DONE)
        log_info("TLS handshake established (%s)", SSL_get_version(ssl));
}

static int sstp_macos_configure_tls(SSL_CTX *context, sstp_option_st *options)
{
    if (options->ca_path || options->crl_file || options->crl_path ||
        (options->enable & SSTP_OPT_CERTWARN))
    {
        log_err("Unsupported option with macOS TLS verification");
        return 0;
    }

    if (!SSL_CTX_set_min_proto_version(context, TLS1_2_VERSION))
        return 0;

    SSL_CTX_set_session_cache_mode(context, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_options(context, SSL_OP_NO_TICKET | SSL_OP_NO_RENEGOTIATION);
    SSL_CTX_set_verify(context, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_info_callback(context, sstp_macos_log_tls);
    SSL_CTX_set_cert_verify_callback(context, sstp_macos_verify_peer, options);
    return 1;
}

#endif
