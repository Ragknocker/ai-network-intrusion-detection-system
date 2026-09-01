def extract_ai_feature_vector(metadata, static_features, yara_res, sig_res):
    """
    Extracts a 15-element normalized numerical feature vector for AI model classification.
    """
    entropy = static_features.get("entropy", 0.0)
    size_bytes = metadata.get("size_bytes", 0)
    api_count = len(static_features.get("suspicious_apis", []))
    yara_count = len(yara_res.get("matches", []))
    sig_count = len(sig_res.get("signatures", []))
    has_pe = 1.0 if static_features.get("has_pe_header") else 0.0
    has_pdf = 1.0 if static_features.get("has_pdf_header") else 0.0
    macro_count = len(static_features.get("macro_indicators", []))

    vector = [
        round(entropy / 8.0, 4),               # 1. Normalized Entropy (0 to 1)
        round(min(1.0, size_bytes / 1000000), 4),# 2. Normalized Size
        round(min(1.0, api_count / 5.0), 4),   # 3. Suspicious API Ratio
        round(min(1.0, yara_count / 3.0), 4),  # 4. YARA Matches Ratio
        round(min(1.0, sig_count / 3.0), 4),   # 5. Signature Match Ratio
        has_pe,                                # 6. PE Flag
        has_pdf,                               # 7. PDF Flag
        round(min(1.0, macro_count / 2.0), 4), # 8. Macro Flag
        1.0 if entropy > 5.3 else 0.0,         # 9. Encrypted/Packed Flag
        0.5 if ".exe" in metadata.get("extension", "") else 0.1, # 10. Ext Risk
        0.0, 0.0, 0.0, 0.0, 0.0
    ]

    return vector
