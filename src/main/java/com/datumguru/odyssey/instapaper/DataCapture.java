package com.datumguru.odyssey.instapaper;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpRequest;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;

import oauth.signpost.exception.OAuthCommunicationException;
import oauth.signpost.exception.OAuthExpectationFailedException;
import oauth.signpost.exception.OAuthMessageSignerException;

public class DataCapture {

    // private DataService service;
    // private OAuthConsumer oAuthConsumer;

    // public DataCapture() {
    // String consumerKey = "AAAAA";
    // String consumerSecret = "BBBBB";
    // String accessToken = "CCCCC";
    // String accessTokenSecret = "DDDDD";

    // setupContext(consumerKey, consumerSecret, accessToken, accessTokenSecret);
    // }

    // public void setupContext(String consumerKey, String consumerSecret, String
    // accessToken, String accessTokenSecret) {
    // this.oAuthConsumer = new CommonsHttpOAuthConsumer(consumerKey,
    // consumerSecret);
    // oAuthConsumer.setTokenWithSecret(accessToken, accessTokenSecret);
    // oAuthConsumer.setSigningStrategy(new AuthorizationHeaderSigningStrategy());
    // }

    // public void authorize(HttpRequestBase httpRequest) throws Exception {
    // try {
    // oAuthConsumer.sign(httpRequest);
    // } catch (OAuthMessageSignerException e) {
    // throw new Exception(e);
    // } catch (OAuthExpectationFailedException e) {
    // throw new Exception(e);
    // } catch (OAuthCommunicationException e) {
    // throw new Exception(e);
    // }
    // }

    // public void executeGetRequest(String customURIString){
    // DefaultHttpClient client = new DefaultHttpClient();
    // client.getParams().setParameter("http.protocol.content-charset", "UTF-8");

    // HttpRequestBase httpRequest = null;
    // URI uri = null;

    // try {
    // uri = new URI(customURIString);
    // } catch (URISyntaxException e) {
    // e.printStackTrace();
    // }

    // String methodtype = "GET";

    // if (methodtype.equals(MethodType.GET.toString())) {
    // httpRequest = new HttpGet(uri);
    // }

    // httpRequest.addHeader("content-type", "application/xml");
    // httpRequest.addHeader("Accept","application/xml");

    // try {
    // authorize(httpRequest);
    // } catch (FMSException e) {
    // e.printStackTrace();
    // }

    // HttpResponse httpResponse = null;
    // try {
    // HttpHost target = new HttpHost(uri.getHost(), -1, uri.getScheme());
    // httpResponse = client.execute(target, httpRequest);
    // System.out.println("Connection status : " + httpResponse.getStatusLine());

    // InputStream inputStraem = httpResponse.getEntity().getContent();

    // StringWriter writer = new StringWriter();
    // IOUtils.copy(inputStraem, writer, "UTF-8");
    // String output = writer.toString();

    // System.out.println(output);
    // }catch(Exception e){
    // e.printStackTrace();
    // }
    // }

    // public static void main(String args[]) {
    // DataCapture withoutDevkitClient = new DataCapture();
    // withoutDevkitClient.executeGetRequest("https://appcenter.intuit.com/api/v1/connection/reconnect");
    // }

    // public static void main(String[] args) {
    // // Connect to instapaper.com webservice
    // try {
    // URL url = new URL("https://www.instapaper.com");
    // HttpURLConnection connection = (HttpURLConnection) url.openConnection();
    // connection.setRequestMethod("GET");

    // // Print response code
    // int responseCode = connection.getResponseCode();
    // System.out.println("Response Code: " + responseCode);

    // // Print response message
    // String responseMessage = connection.getResponseMessage();
    // System.out.println("Response Message: " + responseMessage);

    // // Close the connection
    // connection.disconnect();
    // } catch (Exception e) {
    // e.printStackTrace();
    // }
    // }

    // public static void downloadWebpages(List<String> urls, String outputDir) {
    // for (String url : urls) {
    // try {
    // URL webpage = new URL(url);
    // try (InputStream in = webpage.openStream();
    // BufferedReader reader = new BufferedReader(new InputStreamReader(in));
    // BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(
    // new FileOutputStream(outputDir + "/" + url.hashCode() + ".html")))) {
    // String line;
    // while ((line = reader.readLine()) != null) {
    // writer.write(line);
    // writer.newLine();
    // }
    // }
    // } catch (Exception e) {
    // System.out.println("Failed to download webpage: " + url);
    // e.printStackTrace();
    // }
    // }
    // }

    // public static void main(String[] args) throws IOException,
    // InterruptedException {

    // // Set your Instapaper API credentials
    // String apiKey = "0e877a23ec894e0497d0b8337af8b9b6";
    // String apiSecret = "9d914a697c3d487ea8d4f72bbe47d516";
    // String username = "spamloathing@gmail.com";
    // String password = "X7Tmy8tyuhHK!swVB";

    // // Authenticate with Instapaper API
    // HttpRequest request = HttpRequest.newBuilder()
    // .uri(URI.create("https://www.instapaper.com/api/authenticate"))
    // .POST(HttpRequest.BodyPublishers.ofString(
    // "x_auth_username=" + username
    // + "&x_auth_password=" + password
    // + "&x_auth_mode=" + "client_auth"
    // ))
    // .header("Content-Type", "application/x-www-form-urlencoded")
    // .header("Authorization",
    // "Basic " + java.util.Base64.getEncoder().encodeToString((apiKey + ":" +
    // apiSecret).getBytes()))
    // .build();

    // HttpClient client = HttpClient.newHttpClient();
    // client.
    // HttpResponse<String> response = client.send(request,
    // HttpResponse.BodyHandlers.ofString());
    // String authToken = response.body();

    // System.out.println(authToken);

    // Fetch list of saved URLs
    // HttpRequest savedUrlsRequest = HttpRequest.newBuilder()
    // .uri(URI.create("https://www.instapaper.com/api/1/bookmarks/list"))
    // .header("Authorization", "Basic " + authToken)
    // .build();

    // HttpResponse<String> savedUrlsResponse = client.send(savedUrlsRequest,
    // HttpResponse.BodyHandlers.ofString());
    // String savedUrlsJson = savedUrlsResponse.body();

    // // Save the list of URLs to a file
    // Path outputFile = Path.of("saved_urls.txt");
    // Files.writeString(outputFile, savedUrlsJson);

    // System.out.println("List of saved URLs downloaded successfully.");
    // }

    // Set your Instapaper API credentials
    private static String apiKey = "0e877a23ec894e0497d0b8337af8b9b6";
    private static String apiSecret = "9d914a697c3d487ea8d4f72bbe47d516";
    private static String username = "spamloathing1@gmail.com";
    private static String password = "X7Tmy8tyuhHK!swVB";
    private static String authURL = "https://www.instapaper.com/api/1/oauth/access_token";

    private static final String REQUEST_TOKEN_ENDPOINT = "https://www.instapaper.com/api/1/oauth/request_token";
    private static final String AUTHORIZE_ENDPOINT = "https://www.instapaper.com/api/1/oauth/authorize";
    private static final String ACCESS_TOKEN_ENDPOINT = "https://www.instapaper.com/api/1/oauth/access_token";

    public static void main(String args[]) throws IOException, InterruptedException, OAuthMessageSignerException,
            OAuthExpectationFailedException, OAuthCommunicationException {

        String authorizationHeader = new OAuth1AuthorizationHeaderBuilder()
        .withMethod("POST")
        .withURL(authURL)
        .withConsumerSecret(apiSecret)
        .withTokenSecret(apiKey)
        .withParameter("x_auth_mode", "client_auth")
        .withParameter("x_auth_username", username)
        .withParameter("x_auth_password", password)
        .build();

        System.out.println(authorizationHeader);

        // Build request URI
        URI uri = URI.create(authURL);

        // Create HTTP client
        HttpClient client = HttpClient.newHttpClient();

        // Build the request
        HttpRequest request = HttpRequest.newBuilder()
        .uri(uri)
        .header("Authorization", authorizationHeader)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .POST(HttpRequest.BodyPublishers.noBody())
        .build();

        // Send the request and handle the response
        HttpResponse<String> response = client.send(request,
        HttpResponse.BodyHandlers.ofString());
        System.out.println("Response code: " + response.statusCode());
        System.out.println("Response body: " + response.body());

        // // Create OAuth 1.0a consumer
        // OAuthConsumer consumer = new CommonsHttpOAuthConsumer(apiKey, apiSecret);
        // consumer.setTokenWithSecret(username, password);

        // // Create HTTP client
        // HttpClient httpClient = HttpClients.createDefault();

        // // Create HTTP POST request
        // HttpPost request = new HttpPost(apiUrl);

        // // Add parameters to the request (e.g., url, title)
        // List<BasicNameValuePair> parameters = new ArrayList<>();
        // // parameters.add(new BasicNameValuePair("url", "https://example.com/article"));
        // // parameters.add(new BasicNameValuePair("title", "Example Article"));

        // // Set the parameters as the entity of the request
        // request.setEntity(new UrlEncodedFormEntity(parameters));

        // // Sign the request
        // consumer.sign(request);

        // // Execute the request
        // HttpResponse response = httpClient.execute(request);

        // // Get the response entity
        // HttpEntity entity = response.getEntity();
        // if (entity != null) {
        //     // Convert the entity to a string and print it
        //     String responseString = EntityUtils.toString(entity);
        //     System.out.println("Response: " + responseString);
        // }

    }

}
