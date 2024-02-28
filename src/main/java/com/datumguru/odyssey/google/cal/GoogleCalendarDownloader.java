package com.datumguru.odyssey.google.cal;

// import com.google.api.client.auth.oauth2.Credential;
// import com.google.api.client.extensions.java6.auth.oauth2.AuthorizationCodeInstalledApp;
// import com.google.api.client.extensions.jetty.auth.oauth2.LocalServerReceiver;
// import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
// import com.google.api.client.googleapis.auth.oauth2.GoogleClientSecrets;
// import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
// import com.google.api.client.http.HttpTransport;
// import com.google.api.client.http.javanet.NetHttpTransport;
// import com.google.api.client.json.JsonFactory;
// import com.google.api.client.json.jackson2.JacksonFactory;
// import com.google.api.client.util.DateTime;
// import com.google.api.client.util.store.FileDataStoreFactory;
// import com.google.api.services.calendar.Calendar;
// import com.google.api.services.calendar.CalendarScopes;
// import com.google.api.services.calendar.model.Event;
// import com.google.api.services.calendar.model.Events;

// import java.io.*;
// import java.security.GeneralSecurityException;
// import java.util.Collections;
// import java.util.List;

public class GoogleCalendarDownloader {

    // private static final String APPLICATION_NAME = "Google Calendar API Java Quickstart";
    // private static final JsonFactory JSON_FACTORY = JacksonFactory.getDefaultInstance();
    // private static final String TOKENS_DIRECTORY_PATH = "tokens";

    // private static final List<String> SCOPES = Collections.singletonList(CalendarScopes.CALENDAR_READONLY);
    // private static final String CREDENTIALS_FILE_PATH = "/path/to/credentials.json";

    // public static void main(String... args) throws IOException, GeneralSecurityException {
        
    //     // Build a new authorized API client service.
    //     final NetHttpTransport HTTP_TRANSPORT = GoogleNetHttpTransport.newTrustedTransport();
    //     Calendar service = new Calendar.Builder(HTTP_TRANSPORT, JSON_FACTORY, getCredentials(HTTP_TRANSPORT))
    //             .setApplicationName(APPLICATION_NAME)
    //             .build();

    //     // Define date range for events (next 10 days)
    //     DateTime now = new DateTime(System.currentTimeMillis());
    //     DateTime tenDaysLater = new DateTime(System.currentTimeMillis() + 10 * 24 * 60 * 60 * 1000);

    //     // Fetch the events for the next 10 days
    //     Events events = service.events().list("primary")
    //             .setMaxResults(10)
    //             .setTimeMin(now)
    //             .setTimeMax(tenDaysLater)
    //             .setOrderBy("startTime")
    //             .setSingleEvents(true)
    //             .execute();
    //     List<Event> items = events.getItems();
    //     if (items.isEmpty()) {
    //         System.out.println("No upcoming events found.");
    //     } else {
    //         System.out.println("Upcoming events:");
    //         for (Event event : items) {
    //             DateTime start = event.getStart().getDateTime();
    //             if (start == null) {
    //                 start = event.getStart().getDate();
    //             }
    //             System.out.printf("%s (%s)\n", event.getSummary(), start);
    //         }
    //     }
    // }

    // private static Credential getCredentials(final NetHttpTransport HTTP_TRANSPORT) throws IOException {
    //     // Load client secrets.
    //     InputStream in = GoogleCalendarDownloader.class.getResourceAsStream(CREDENTIALS_FILE_PATH);
    //     GoogleClientSecrets clientSecrets = GoogleClientSecrets.load(JSON_FACTORY, new InputStreamReader(in));

    //     // Build flow and trigger user authorization request.
    //     GoogleAuthorizationCodeFlow flow = new GoogleAuthorizationCodeFlow.Builder(
    //             HTTP_TRANSPORT, JSON_FACTORY, clientSecrets, SCOPES)
    //             .setDataStoreFactory(new FileDataStoreFactory(new File(TOKENS_DIRECTORY_PATH)))
    //             .setAccessType("offline")
    //             .build();
    //     LocalServerReceiver receiver = new LocalServerReceiver.Builder().setPort(8888).build();
    //     return new AuthorizationCodeInstalledApp(flow, receiver).authorize("user");
    // }
}
