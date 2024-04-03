#include <iostream>
#include <cstdio>
#include <string>
#include <array>
#include <sys/select.h>
#include <unistd.h>
#include "mongoose.h"
#include <format>
#include "mg_fd_netif.h"
#include "tun_interface.h"

using std::string, std::string_view, std::data, std::size;
using std::array;
using std::format;

using cstr_unique_ptr = std::unique_ptr<char, decltype([](const char* c)
{
    delete(c);
})>;


string session_token{};
string csrf_token{};

static std::array<char, 220> log_buf{};
static size_t prefix_end{};

static const char* to_log_level_str(const int level)
{
    switch (level)
    {
    case MG_LL_ERROR:
        return "ERROR";
    case MG_LL_INFO:
        return "INFO";
    case MG_LL_DEBUG:
        return "DEBUG";
    case MG_LL_VERBOSE:
        return "VERBOSE";
    default:
        return "?";
    }
}

void mg_log_prefix(const int ll,
                   const char* file,
                   const int line,
                   const char* fname)
{
    const char* p = strrchr(file, '/');
    if (p == nullptr)
    {
        p = strrchr(file, '\\');
    }
    const char* level_str = to_log_level_str(ll);
    uint64_t millis = mg_millis();
    const char* file_str = p == nullptr ? file : p + 1;
    size_t n = mg_snprintf(data(log_buf), size(log_buf),
                           "%-6llx %s %s:%d:%s ",
                           millis,
                           level_str,
                           file_str,
                           line,
                           fname);
    prefix_end = n;
}

void mg_log(const char* fmt, ...)
{
    va_list args{};
    char* buf_ptr = data(log_buf) + prefix_end;
    size_t buf_size = size(log_buf) - prefix_end;
    va_start(args, fmt);
    mg_vsnprintf(buf_ptr, buf_size, fmt, &args);
    va_end(args);
    std::cout << log_buf.data() << std::endl;
}

void tls_init(mg_tls_opts& tls_opts)
{
    tls_opts = {};

    tls_opts.ca = mg_file_read(&mg_fs_posix, "snarfle.crt");
    tls_opts.cert = mg_file_read(&mg_fs_posix, "antistar.crt");
    tls_opts.key = mg_file_read(&mg_fs_posix, "antistar.key");

    assert(tls_opts.ca.ptr != nullptr && tls_opts.cert.ptr != nullptr && tls_opts.key.ptr != nullptr);
}


static string get_form_field(const mg_http_message* hm, const string& name)
{
    string result{};
    result.resize(32, ' ');
    const int get_ret = mg_http_get_var(&hm->body, name.c_str(), data(result), size(result));
    if (get_ret >= 0)
    {
        result.resize(static_cast<size_t>(get_ret));
    }
    else
    {
        result.clear();
    }
    return result;
}

static bool get_cookie(mg_http_message* hm, const char* name, string_view& session_id_str)
{
    const mg_str* cookie = mg_http_get_header(hm, "Cookie");
    if (cookie == nullptr)
    {
        session_id_str = {};
        return false;
    }
    mg_str sessionid{};
    sessionid = mg_http_get_header_var(*cookie, mg_str(name));
    session_id_str = {sessionid.ptr, sessionid.len};
    return !session_id_str.empty();
}

static const char* extra_mime_types = "webp=image/webp";

// Mongoose event handler function, gets called by the mg_mgr_poll()
static void fn_http_server(struct mg_connection* c, const int ev, void* ev_data)
{
    if (ev == MG_EV_HTTP_MSG)
    {
        auto* hm = static_cast<mg_http_message*>(ev_data);

        // CSP header: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy
        // Prevent inline scripts and styles, and only allow scripts, styles, etc. from the same origin
        string standard_headers{"Content-Security-Policy: default-src 'self'\r\n"};

        if (const mg_str* host = mg_http_get_header(hm, "Host"); host != nullptr)
        {
            // DNS rebinding defense: only allow our own hostname / IP address
            // https://en.wikipedia.org/wiki/DNS_rebinding
            string_view host_str{host->ptr, host->len};
            size_t port_idx = host_str.find_last_of(':');
            host_str = host_str.substr(0, port_idx);
            if (host_str != "localhost" && host_str != "127.0.0.1")
            {
                mg_http_reply(c, 403, standard_headers.c_str(), "");
                return;
            }
        }
        else
        {
            // ho Host header; ignore
        }

        // unauthenticated access
        // -----------------------
        if (mg_http_match_uri(hm, "/") && mg_vcmp(&hm->method, "GET") == 0)
        {
            string location_header = format("{}Location: /index.html\r\n", standard_headers);
            mg_http_reply(c, 302, location_header.c_str(), "");
            return;
        }
        if ((mg_http_match_uri(hm, "/index.html")
                || mg_http_match_uri(hm, "/assets/*")
                || mg_http_match_uri(hm, "/favicon.ico")
                || mg_http_match_uri(hm, "/images/*")
                || mg_http_match_uri(hm, "/signon.html"))
            && (mg_vcmp(&hm->method, "GET") == 0
                || mg_vcmp(&hm->method, "HEAD") == 0))
        {
            string cache_headers = standard_headers;
            if (mg_http_match_uri(hm, "/assets/*"))
            {
                cache_headers = format("{}Cache-Control: max-age=3600\r\n", standard_headers);
            }
            else if (mg_http_match_uri(hm, "/*.html"))
            {
                cache_headers = format("{}Cache-Control: private\r\n", standard_headers);
            }

            mg_http_serve_opts so{
                .root_dir = "",
                .extra_headers = cache_headers.c_str(),
                .fs = &mg_fs_packed,
                .mime_types = extra_mime_types
            };
            mg_http_serve_dir(c, hm, &so);

            return;
        }

        if (mg_http_match_uri(hm, "/csrf-token") && mg_vcmp(&hm->method, "GET") == 0)
        {
            string reply_headers = format(
                "{}Content-Type: application/json\r\nCache-Control: no-store, private\r\n", standard_headers);
            mg_http_reply(c, 200, reply_headers.c_str(),
                          "{\"csrfToken\":%m}",
                          mg_print_esc, size(csrf_token), data(csrf_token));
            return;
        }

        // authenticated access
        // ---------------------
        string csrf_token_str{};
        mg_str* csrf_header = mg_http_get_header(hm, "X-CSRF-Token");
        if (csrf_header != nullptr)
        {
            csrf_token_str = {csrf_header->ptr, csrf_header->len};
        }
        bool has_csrf_token = !csrf_token_str.empty();

        bool csrf_token_matches = has_csrf_token && csrf_token_str == csrf_token;

        if (!csrf_token_matches
            && mg_vcmp(&hm->method, "GET") != 0
            && mg_vcmp(&hm->method, "HEAD") != 0)
        {
            // require CSRF token except for HEAD and GET
            mg_http_reply(c, 403, standard_headers.c_str(), "");
            return;
        }

        if (mg_http_match_uri(hm, "/session") && mg_vcmp(&hm->method, "POST") == 0)
        {
            const mg_str* content_type = mg_http_get_header(hm, "Content-Type");
            if (content_type == nullptr || mg_vcasecmp(content_type, "application/json") != 0)
            {
                mg_http_reply(c, 400, standard_headers.c_str(),
                              "Content-Type must be application/json");
                return;
            }

            char* get_ret = mg_json_get_str(hm->body, "$.password");
            string password{};
            if (get_ret != nullptr)
            {
                password = get_ret;
            }
            if (password == "hoodoo")
            {
                // return sucess
                string cookie_header = format(
                    "{}Set-Cookie: mgsession={}\r\nContent-Type: application/json\r\nCache-Control: private\r\n",
                    standard_headers,
                    session_token);
                mg_http_reply(c, 200, cookie_header.c_str(),
                              "{%m:%m}", MG_ESC("redirect"), MG_ESC("/dashboard.html"));
                return;
            }
            // login failed
            string cache_header = format(
                "{}Cache-Control: private\r\n", standard_headers);
            mg_http_reply(c, 401, cache_header.c_str(), "");
            return;
        }

        // session id check
        string_view session_id_str;
        bool has_session_id = get_cookie(hm, "mgsession", session_id_str);
        bool is_session_id_valid = has_session_id && session_id_str == session_token;
        if (!is_session_id_valid)
        {
            mg_http_reply(c, 403, standard_headers.c_str(), "");
            return;
        }

        string cache_headers = format("{}Cache-Control: private\r\n", standard_headers);

        if (mg_http_match_uri(hm, "/dashboard.html") && mg_vcmp(&hm->method, "GET") == 0)
        {
            mg_http_serve_opts so{
                .root_dir = "",
                .extra_headers = cache_headers.c_str(),
                .fs = &mg_fs_packed,
                .mime_types = extra_mime_types
            };
            mg_http_serve_file(c, hm, "/dashboard.html", &so);
        }
        else
        {
            mg_http_reply(c, 404, standard_headers.c_str(), "Not found");
        }
    }
}

struct mqtt_conn_info
{
    unsigned id{};
    bool connected{};
};

struct mqtt_client_context
{
    unsigned id{};
    bool hs_inprogress{};
};

static mqtt_client_context mqtt_ctx{};

static void send_mqtt_status(mg_connection* conn, const mqtt_conn_info* cinfo)
{
    mg_mqtt_opts msg{};
    msg.topic = mg_str("test");
    array<char, 60> payload{};
    uint64_t tick = mg_millis();
    size_t payload_len = mg_snprintf(data(payload), size(payload),
                                     "{%m:%llu,%m:%u}",
                                     MG_ESC("timestamp"), tick,
                                     MG_ESC("conn_id"), cinfo->id);
    msg.message = mg_str_n(data(payload), payload_len);
    mg_mqtt_pub(conn, &msg);
}

static void send_mqtt_reply(mg_connection* conn, const mqtt_conn_info* cinfo, mg_str topic_str, mg_str corr_id_str)
{
    mg_mqtt_opts msg{};
    msg.topic = topic_str;

    array<char, 512> payload{};
    uint64_t tick = mg_millis();
    size_t payload_len = mg_snprintf(data(payload), size(payload),
                                     "{%m:%llu,%m:%u,%m:%m}",
                                     MG_ESC("timestamp"), tick,
                                     MG_ESC("conn_id"), cinfo->id,
                                     MG_ESC("correlation_id"), mg_print_esc, corr_id_str.len, corr_id_str.ptr);

    if (payload_len >= size(payload))
    {
        printf("payload too large\n");
        return;
    }
    msg.message = mg_str_n(data(payload), payload_len);
    mg_mqtt_pub(conn, &msg);
}

static bool send_mqtt_connack(mg_connection* conn, const mg_mqtt_message* mm)
{
    if (mm->dgram.len <= 10u)
    {
        MG_INFO(("invalid CONNECT"));
        conn->is_closing = true;
        return false;
    }
    uint8_t connack_response = 0x00u;
    const char* vh = static_cast<const char*>(mm->dgram.ptr) + 2;
    const size_t vl = static_cast<uint8_t>(mm->dgram.ptr[1]);
    if (vl < 9u)
    {
        MG_INFO(("invalid CONNECT"));
        conn->is_closing = true;
        return false;
    }
    if (vh[0] != '\x00' || vh[1] != '\x04' || vh[2] != 'M' || vh[3] != 'Q' || vh[4] != 'T' || vh[5] != 'T')
    {
        MG_INFO(("invalid CONNECT"));
        conn->is_closing = true;
        return false;
    }
    uint8_t proto_ver = static_cast<uint8_t>(vh[6]);
    if (proto_ver != 0x04 /* MQTT 3.1.1 */)
    {
        MG_INFO(("unsupported protocol version %x", proto_ver));
        connack_response = 0x01u;
    }
    uint8_t conn_flags = static_cast<uint8_t>(vh[7]);
    if (conn_flags != 0x02u /* 0x02u CLEAN SESSION */)
    {
        MG_INFO(("invalid CONNECT flags %x", conn_flags));
        connack_response = 0x01u;
    }
    const array<uint8_t, 2> response{0x00u, connack_response};
    mg_mqtt_send_header(conn, MQTT_CMD_CONNACK, 0, sizeof(response));
    mg_send(conn, data(response), sizeof(response));
    return connack_response == 0x00u;
}

static void mqtt_client_fn(mg_connection* mg_connection, const int ev, void* ev_data)
{
    auto* cinfo = reinterpret_cast<mqtt_conn_info*>(mg_connection->fn_data);
    if (cinfo == nullptr || mqtt_ctx.id != cinfo->id)
    {
        // if more than one connection is active, we need to ignore events from the wrong one
        // and close it
        mg_connection->is_closing = true;
        return;
    }

    switch (ev)
    {
    case MG_EV_MQTT_MSG:
        {
            auto mm = static_cast<mg_mqtt_message*>(ev_data);
            string_view topic{mm->topic.ptr, mm->topic.len};
            if (topic == "$SYS/broker/clients/active")
            {
                printf("active clients: %.*s\n",
                       static_cast<int>(mm->data.len), mm->data.ptr);
            }
            else if (topic == "test_req")
            {
                printf("test_req message: %.*s\n",
                       static_cast<int>(mm->data.len), mm->data.ptr);
                const cstr_unique_ptr corr_id_str(
                    mg_json_get_str(mm->data, "$.correlation_id"));
                const cstr_unique_ptr topic_str(
                    mg_json_get_str(mm->data, "$.topic"));
                if (corr_id_str && *corr_id_str != '\0'
                    && topic_str && *topic_str != '\0')
                {
                    send_mqtt_reply(mg_connection, cinfo, mg_str(topic_str.get()), mg_str(corr_id_str.get()));
                }
                else
                {
                    printf("missing correlation_id %p or topic %p\n", corr_id_str.get(), topic_str.get());
                }
            }
        }
        break;
    case MG_EV_USER:
        {
            if (!cinfo->connected)
            {
                return;
            }
            // send_mqtt_status(conn);
        }
        break;
    case MG_EV_CONNECT:
        {
            mqtt_ctx.hs_inprogress = true;
            mg_tls_opts tls_opts_mqtt{};
            tls_init(tls_opts_mqtt);
            // tls_opts_mqtt.name = mg_str("openwrt-er");
            mg_tls_init(mg_connection, &tls_opts_mqtt);
        }
        break;
    case MG_EV_TLS_HS:
        {
            mqtt_ctx.hs_inprogress = false;
        }
        break;
    case MG_EV_MQTT_OPEN:
        {
            printf("connected to mqtt\n");
            mg_mqtt_opts sub_opts{};
            sub_opts.topic = mg_str("$SYS/broker/clients/active");
            mg_mqtt_sub(mg_connection, &sub_opts);
            sub_opts.topic = mg_str("test_req");
            mg_mqtt_sub(mg_connection, &sub_opts);
        }
        break;
    case MG_EV_MQTT_CMD:
        {
            auto mm = static_cast<mg_mqtt_message*>(ev_data);
            switch (mm->cmd)
            {
            case MQTT_CMD_CONNACK:
                {
                    cinfo->connected = true;
                }
                break;
            case MQTT_CMD_CONNECT:
                {
                    if (send_mqtt_connack(mg_connection, mm))
                    {
                        printf("connected from mqtt\n");
                        mg_mqtt_opts sub_opts{};
                        sub_opts.topic = mg_str("$SYS/broker/clients/active");
                        mg_mqtt_sub(mg_connection, &sub_opts);
                        sub_opts.topic = mg_str("test_req");
                        mg_mqtt_sub(mg_connection, &sub_opts);
                    }
                    else
                    {
                        printf("rejected CONNECT from mqtt");
                    }
                }
                break;
            case MQTT_CMD_PINGREQ:
                {
                    mg_mqtt_pong(mg_connection);
                }
                break;
            default:
                break;
            }
            if (mm->cmd == MQTT_CMD_CONNACK)
            {
                cinfo->connected = true;
            }
        }
        break;
    case MG_EV_CLOSE:
        {
            delete cinfo;
            mg_connection->fn_data = nullptr;
            printf("mqtt closed\n");
            mqtt_ctx.hs_inprogress = false;
        }
        break;
    case MG_EV_ERROR:
        {
            const char* err_msg = static_cast<const char*>(ev_data);
            printf("mqtt error %s\n", err_msg);
            mqtt_ctx.hs_inprogress = false;
        }
        break;

    default:
        break;
    }
}

static void mqtt_client_timer_fn(void* p)
{
    assert(p);
    mg_mgr &mgr = *static_cast<mg_mgr*>(p);
    for(mg_connection *conn = mgr.conns; conn; conn = conn->next)
    {
        if (conn->fn == mqtt_client_fn)
        {
            if(conn->is_draining)
            {
                continue;
            }
            mg_call(conn, MG_EV_USER, nullptr);
        }
    }
}

static void telnet_server_demo(mg_mgr& mgr)
{
    mg_listen(&mgr, "tcp://0.0.0.0:2222", [](mg_connection* nc, const int ev, void* /*ev_data*/)
    {
        if (ev == MG_EV_ACCEPT)
        {
            mg_printf(nc, "Hello! Remote IP: %M\n", mg_print_ip, &nc->rem);
        }
        else if (ev == MG_EV_READ)
        {
            mg_send(nc, nc->recv.buf, nc->recv.len);

            // close if we receive a '.' char in the first byte
            if (nc->recv.len > 0 && nc->recv.buf[0] == '.')
            {
                mg_send(nc, static_cast<const char*>("Good bye!\n"), 10);
                nc->is_draining = true;
            }
            mg_iobuf_del(&nc->recv, 0, nc->recv.len);
        }
    }, nullptr);
}

static bool is_stdin_readable()
{
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(0, &readfds);

    // Do not wait
    timeval tv{};
    tv.tv_sec = 0;
    tv.tv_usec = 0;

    int select_ret = select(1, &readfds, nullptr, nullptr, &tv);

    if (select_ret == -1)
    {
        perror("select()");
    }
    else if (select_ret)
    {
        return true;
    }

    return false;
}

static void telnet_client_fn(mg_connection* mg_connection, const int ev, void* ev_data)
{
    if (ev == MG_EV_CONNECT)
    {
        printf("telnet connected");
        mg_send(mg_connection, reinterpret_cast<const void*>("hello\n"), 6);
        mg_connection->is_draining = true;
    }
    else if (ev == MG_EV_ERROR)
    {
        char* msg = static_cast<char*>(ev_data);
        printf("telnet error: %s\n", msg);
    }
    else if (ev == MG_EV_POLL)
    {
        printf("telnet_client_fn .\n");
    }
}

static void tls_client_fn(mg_connection* mg_connection, const int ev, void* ev_data)
{
    if (ev == MG_EV_CONNECT)
    {
        printf("tls connected\n");
        mg_tls_opts tls_opts_tcp{};
        tls_init(tls_opts_tcp);
        mg_tls_init(mg_connection, &tls_opts_tcp);
    }
    else if (ev == MG_EV_TLS_HS)
    {
        printf("tls handshake\n");
    }
    else if (ev == MG_EV_ERROR)
    {
        char* msg = static_cast<char*>(ev_data);
        printf("tls error: %s\n", msg);
    }
}

static void tls_server_fn([[maybe_unused]] mg_connection* mg_connection, const int ev, void* ev_data)
{
    if (ev == MG_EV_ACCEPT)
    {
        printf("tls connected\n");
        mg_tls_opts tls_opts_tcp{};
        tls_init(tls_opts_tcp);
    }
    else if (ev == MG_EV_TLS_HS)
    {
        printf("tls handshake\n");
    }
    else if (ev == MG_EV_ERROR)
    {
        char* msg = static_cast<char*>(ev_data);
        printf("tls error: %s\n", msg);
    }
}

static uint32_t net_u32(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    // return in network byte order
    return static_cast<uint32_t>(a)
           | static_cast<uint32_t>(b) << 8u
           | static_cast<uint32_t>(c) << 16u
           | static_cast<uint32_t>(d) << 24u;
}

array<uint8_t, 8> generate_locally_administered_mac() {
    union {
        uint8_t id[8];
        uint64_t mac;
    } id{};

    id.mac = mg_millis();

    return {2, id.id[3], id.id[4], id.id[5], id.id[6], id.id[7]};
}

int main(int argc, char** argv)
{
    if (argc == 2)
    {
        string arg0 = argv[0];
        string arg1 = argv[1];

        if (arg1 == "--test")
        {
            std::cout << "Test mode" << std::endl;
            return 1;
        }
    }
    mg_mgr mgr{};
    mg_mgr_init(&mgr); // Init manager
    mg_log_set(MG_LL_DEBUG); // Set debug log level. Default is MG_LL_INFO

#ifdef MG_ENABLE_TCPIP
    mg_tcpip_if mif{};
    std::array<uint8_t, 8> mac_addr = generate_locally_administered_mac();
    std::copy_n(mac_addr.begin(), std::size(mif.mac), mif.mac);
    mif.driver = &mg_fd_netif_tcpip;
    mg_fd_netif_state netif_state{};
    mif.driver_data = &netif_state;
    // static configuration:
    mif.ip = net_u32(10u, 13u, 1u, 1u);
    mif.mask = net_u32(255u, 255u, 255u, 0u);
    mif.gw = 0u;

    tun_interface tun{33};
    try
    {
        tun.create();

        string tun_name = tun.device_name();

        fprintf(stderr, "Utun interface is up.. Configure IPv4 using \"ifconfig %s _ipA_ _ipB_\"\n", tun_name.c_str());
        fprintf(stderr, "Then (e.g.) ping _ipB_\n");


        fprintf(stderr, "Waiting for address assignment...\n");
        bool found_address = false;
        tun_address_pair addresses{};
        for (size_t reps = 0; reps < 30; ++reps) {
            addresses = tun.get_assigned_addresses();
            if (addresses) {
                found_address = true;
                const std::string addr_str = to_string(addresses.addr);
                const std::string dstaddr_str = to_string(addresses.dstaddr);
                fprintf(stderr, "Assigned address %s, dstaddr %s\n", addr_str.c_str(), dstaddr_str.c_str());
                break;
            }
            sleep(1);
        }
        if (!found_address) {
            fprintf(stderr, "No address assigned - aborting\n");
            exit(1);
        }
        tun.set_nonblocking();
        mif.ip = addresses.dstaddr;
        netif_state.fd = tun.get_fd();
    } catch (std::runtime_error &e) {
        fprintf(stderr, "Error: %s\n", e.what());
        exit(1);
    }

    fprintf(stderr, "Waiting to start, press enter...");
    int getc_ret = getchar();
    if (getc_ret == EOF) {
        throw std::runtime_error("getchar failed");
    }


    mg_tcpip_init(&mgr, &mif);

#endif // MG_ENABLE_TCPIP
    // http_server_demo(mgr);
    // telnet_server_demo(mgr);

    mg_connection* mqtt_conn{};

    //    mg_http_listen(&mgr, "http://0.0.0.0:8222", fn_http_server, nullptr);

    // mg_listen(&mgr, "tcp://localhost:2222", tls_server_fn, nullptr);

    session_token.resize(20);
    mg_random_str(data(session_token), size(session_token) + 1u);
    csrf_token.resize(20);
    mg_random_str(data(csrf_token), size(csrf_token) + 1u);

    unsigned conn_id{};

    mg_timer_add(&mgr,
                 5000u,
                 MG_TIMER_REPEAT,
                 mqtt_client_timer_fn,
                 &mgr);

    while (true)
    {
        mg_mgr_poll(&mgr, 1000);

        usleep(10'000); // sleep 10ms

        // check if stdin is readable, if any input then initiate a connection
        bool should_connect = false;
        while (is_stdin_readable())
        {
            should_connect = true;
            getchar();
        }

        if (should_connect)
        {
            // mg_connect(&mgr, "tcp://localhost:2222", telnet_client_fn, nullptr);
            //             mg_connect(&mgr, "tcp://localhost:2222", tls_client_fn, nullptr);

            if (mqtt_conn != nullptr)
            {
                for(mg_connection *conn = mgr.conns; conn != nullptr; conn = conn->next)
                {
                    if (conn != mqtt_conn)
                    {
                        continue;
                    }
                    if(conn->is_draining || conn->is_closing)
                    {
                        continue;
                    }
                    mg_mqtt_opts disconnect_opts{};
                    mg_mqtt_disconnect(mqtt_conn, &disconnect_opts);
                    mqtt_conn->is_draining = true;
                    break;
                }
            }

            ++conn_id;
            mqtt_ctx.id = conn_id;
            auto *conn_info = new mqtt_conn_info{.id = conn_id};

            // mqtt_conn = mg_mqtt_connect(&mgr, "mqtts://192.168.192.130:8833", nullptr,
            //                             mqtt_client_fn,
            //                             conn_info);
            mqtt_conn = mg_mqtt_connect(&mgr, "mqtts://10.12.1.1:8833", nullptr,
                                        mqtt_client_fn,
                                        conn_info);
        }
    }

    return 0;
}
