# Event System

The system is event-driven: producers raise typed events, and any number of
components that registered as listeners for that type receive them. There is no
central dispatcher object -- dispatch is a compile-time-typed static registry
keyed by event type.

## The two templates

`core/include/services_sdk/resources/event.h`:

```cpp
template <typename EventType, typename ReplyType = void>
class Event : public EventImpl<EventType, ReplyType> {};
```

`core/include/services_sdk/resources/listener.h`:

```cpp
template <typename EventType>
class Listener : public ListenerImpl<EventType, typename EventType::EventReturnType> {};
```

An event type derives from `Event<Self, Reply>` (CRTP). A listener derives from
`Listener<ThatEvent>` and overrides a handler. The reply type on the event
decides which dispatch primitives exist.

## notify() vs query()

From `core/include/services_sdk/resources/event_is/event_impl.h`:

- **`ReplyType = void`** (the default) -> only `notify()` exists. Fire-and-forget
  broadcast to every listener. Use for "something happened" signals.

  ```cpp
  class ConfigLoadedEvent : public Event<ConfigLoadedEvent> {};
  // raise it:
  ConfigLoadedEvent().notify();
  ```

- **non-void `ReplyType`** -> `notify()`, `query()`, and `performNamedQuery()`
  exist. `query()` returns a `std::vector<ReplyType>` -- one entry per listener
  that responded; `performNamedQuery()` pairs each reply with the listener's
  name (useful for debugging which component answered).

  ```cpp
  class WhoOwnsAssetEvent : public Event<WhoOwnsAssetEvent, Maybe<AssetId>> {
  public:
      explicit WhoOwnsAssetEvent(std::string h) : host(std::move(h)) {}
      const std::string & getHost() const { return host; }
  private:
      std::string host;
  };

  // gather all answers:
  std::vector<Maybe<AssetId>> answers = WhoOwnsAssetEvent("api.example.com").query();
  ```

The event object is `dynamic_cast` to the concrete type internally, which is why
`EventImpl` keeps a `virtual ~EventImpl()` -- the event must be polymorphic.

## Writing a listener

```cpp
class AssetResolver
    : public Component,
      public Listener<WhoOwnsAssetEvent>   // non-void reply -> implement respond()
{
public:
    Maybe<AssetId> respond(const WhoOwnsAssetEvent &e) override {
        return lookup(e.getHost());
    }
    // Listener<T> auto-registers in its ListenerImpl base ctor; call
    // registerListener()/unregisterListener() (from the base) in init()/fini()
    // when you want activation tied to the component lifecycle.
};
```

For a `void`-reply event the handler is `void upon(const EventType &)` instead
of `respond`. A class can listen to many event types by inheriting multiple
`Listener<...>` bases.

## How the HTTP pipeline uses events

HTTP traffic arrives over shared-memory IPC from the nginx attachment, is
decoded, and is driven through the security components as a fixed event
sequence (defined in `components/include/http_inspection_events.h`; see also
[WAAP_HTTP_TRANSACTION.md](../../WAAP_HTTP_TRANSACTION.md)):

```
NewHttpTransactionEvent
  -> HttpRequestHeaderEvent     (per header)
  -> HttpRequestBodyEvent       (per body chunk)
  -> EndRequestEvent
  -> ResponseCodeEvent
  -> HttpResponseHeaderEvent    (per header)
  -> HttpResponseBodyEvent      (per body chunk)
  -> EndTransactionEvent
```

The inspection events reply with a verdict (allow / drop / inject custom
response), so they are `query()`-style events: each security component
(`WaapComponent`, `IPSComp`, `RateLimit`, ...) is a `Listener` that inspects the
chunk and returns its verdict, and the HTTP manager combines the verdicts to
decide what nginx should do with the request.

## When to use events vs Singleton lookup

- Use a **Singleton interface** when you need *the* implementation of a service
  and a direct call (request/response with one well-known owner): config,
  messaging, the table, time.
- Use an **event** when zero-or-more components may care, when the producer
  should not know the consumers, or when you want to fan a query out to whoever
  can answer.
