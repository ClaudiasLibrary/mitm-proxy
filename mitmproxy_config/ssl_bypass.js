// Example Frida script to bypass SSL Pinning in Android apps
Java.perform(function() {
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    var TrustManagerFactory = Java.use("javax.net.ssl.TrustManagerFactory");
    var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");

    var TrustManager = Java.registerClass({
        name: "com.example.TrustManager",
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() {
                return null;
            }
        }
    });

    var tmf = TrustManagerFactory.getInstance("X.509");
    tmf.init(null);

    var context = SSLContext.getInstance("TLS");
    context.init(null, [TrustManager.$new()], null);
    SSLContext.setDefault(context);
    console.log("[+] SSL Pinning Bypass Successful");
});
