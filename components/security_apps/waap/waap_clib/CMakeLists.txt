include_directories(../include)
add_library(waap_clib
    Csrf.cc
    CsrfPolicy.cc
    ContentTypeParser.cc
    CidrMatch.cc
    DeepParser.cc
    KeyStack.cc
    ParserBase.cc
    ParserBinary.cc
    ParserHdrValue.cc
    ParserJson.cc
    ParserMultipartForm.cc
    ParserRaw.cc
    ParserUrlEncode.cc
    ParserXML.cc
    ParserDelimiter.cc
    ParserConfluence.cc
    ParserHTML.cc
    PatternMatcher.cc
    PHPSerializedDataParser.cc
    WaapScores.cc
    WaapKeywords.cc
    Waf2Engine.cc
    Waf2EngineGetters.cc
    WaapScanner.cc
    WaapRegexPreconditions.cc
    Waf2Regex.cc
    WaapAssetState.cc
    Signatures.cc
    Waf2Util.cc
    WaapConfigBase.cc
    WaapConfigApi.cc
    WaapConfigApplication.cc
    BehaviorAnalysis.cc
    FpMitigation.cc
    D2Main.cc
    DeepAnalyzer.cc
    Telemetry.cc
    WaapOverride.cc
    ScoreBuilder.cc
    WaapTrigger.cc
    WaapDecision.cc
    WaapResponseInspectReasons.cc
    WaapResponseInjectReasons.cc
    WaapResultJson.cc
    WaapAssetStatesManager.cc
    Serializator.cc
    IndicatorsFilterBase.cc
    TypeIndicatorsFilter.cc
    KeywordIndicatorFilter.cc
    WaapOverrideFunctor.cc
    WaapValueStatsAnalyzer.cc
    TrustedSources.cc
    WaapParameters.cc
    IndicatorsFiltersManager.cc
    ConfidenceFile.cc
    ConfidenceCalculator.cc
    TrustedSourcesConfidence.cc
    RateLimiter.cc
    RateLimiting.cc
    ErrorLimiting.cc
    WaapErrorDisclosurePolicy.cc
    WaapOpenRedirect.cc
    WaapOpenRedirectPolicy.cc
    KeywordTypeValidator.cc
    SecurityHeadersPolicy.cc
    UserLimitsPolicy.cc
    ScannerDetector.cc
    TuningDecision.cc
    ScanResult.cc
    SingleDecision.cc
    DecisionFactory.cc
    AutonomousSecurityDecision.cc
    CsrfDecision.cc
    OpenRedirectDecision.cc
    ErrorDisclosureDecision.cc
    RateLimitingDecision.cc
    UserLimitsDecision.cc
    ErrorLimitingDecision.cc
    WaapConversions.cc
    SyncLearningNotification.cc
    LogGenWrapper.cc
    WaapSampleValue.cc
    ParserGql.cc
    ParserPercentEncode.cc
    ParserPairs.cc
)

add_definitions("-Wno-unused-function")
add_definitions("-Wno-unused-parameter")
add_definitions("-Wno-deprecated-declarations")

#target_link_libraries(waap_clib pm buffers generic_rulebase ip_utilities connkey report_messaging compression_utils -lz)

# Include static headers
#target_link_libraries(waap_clib)

#target_link_libraries(waap_clib logging event_is metric)

#link_directories(${BOOST_ROOT}/lib)
#link_directories(${ng_module_osrc_zlib_path}/include)

# Link with all the libraries
#target_link_libraries(waap_clib -lresolv)
#target_link_libraries(waap_clib ${PCRE2_LIBRARIES})
#target_link_libraries(waap_clib ${YAJL_LIBRARIES})
#target_link_libraries(waap_clib ${LIBXML2_LIBRARIES})
#target_link_libraries(waap_clib "${ng_module_osrc_openssl_path}/lib/libcrypto.so")
#target_link_libraries(waap_clib "${ng_module_osrc_boost_path}/lib/libboost_context.so")
#target_link_libraries(waap_clib "${ng_module_osrc_boost_path}/lib/libboost_regex.so")
