add_unit_test(
    environment_ut
    "context_ut.cc;parsing_ut.cc;base_evaluators_ut.cc;environment_rest_ut.cc;span_ut.cc;trace_ut.cc;tracing_ut.cc;environment_ut.cc"
    "environment;singleton;rest;mainloop;metric;-lboost_context;event_is;-lboost_regex"
)
