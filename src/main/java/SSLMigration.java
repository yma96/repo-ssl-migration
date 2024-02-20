import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import java.io.IOException;
import java.net.ConnectException;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SSLMigration
{
    private static final TrustManager MOCK_TRUST_MANAGER = new X509ExtendedTrustManager()
    {
        @Override
        public void checkClientTrusted( X509Certificate[] chain, String authType, Socket socket )
        {

        }

        @Override
        public void checkServerTrusted( X509Certificate[] chain, String authType, Socket socket )
        {

        }

        @Override
        public void checkClientTrusted( X509Certificate[] chain, String authType, SSLEngine engine )
        {

        }

        @Override
        public void checkServerTrusted( X509Certificate[] chain, String authType, SSLEngine engine )
        {

        }

        @Override
        public java.security.cert.X509Certificate[] getAcceptedIssuers()
        {
            return new java.security.cert.X509Certificate[0];
        }

        @Override
        public void checkClientTrusted( X509Certificate[] chain, String authType )
        {

        }

        @Override
        public void checkServerTrusted( java.security.cert.X509Certificate[] chain, String authType )
        {
        }
    };

    public static void main( String[] args )
            throws InterruptedException, IOException, NoSuchAlgorithmException, KeyManagementException
    {
        Logger logger = LoggerFactory.getLogger( SSLMigration.class );
        String route = "https://indy-gateway.psi.redhat.com";
        String token = "";
        // Get all need to be migrated
        SSLContext sslContext = SSLContext.getInstance( "SSL" );
        sslContext.init( null, new TrustManager[] { MOCK_TRUST_MANAGER }, new SecureRandom() );
        HttpClient client = HttpClient.newBuilder()
                                      .sslContext( sslContext )
                                      .connectTimeout( Duration.ofSeconds( 30 ) )
                                      .version( HttpClient.Version.HTTP_1_1 )
                                      .build();
        HttpRequest request = HttpRequest.newBuilder()
                                         .uri( URI.create(
                                                 route + "/api/admin/stores/query/remotes/all?enabled=true" ) )
                                         .build();
        HttpResponse response = client.send( request, HttpResponse.BodyHandlers.ofString() );

        JSONObject allJson = new JSONObject( (String) response.body() );
        JSONArray allRemote = allJson.getJSONArray( "items" );
        logger.info( "Total enabled remote repos: {}", allRemote.length() );

        Map<String, String> migrateRepos = new HashMap<>();
        List<String> impliedRepos = new ArrayList<>();
        for ( int i = 0; i < allRemote.length(); i++ )
        {
            JSONObject obj = allRemote.getJSONObject( i );
            if ( obj.getString( "url" ).startsWith( "http://" ) )
            {
                migrateRepos.put( obj.getString( "key" ), obj.getString( "url" ) );
            }
            String repoName = obj.getString( "key" ).split( ":" )[2];
            if ( repoName.startsWith( "i-" ) )
            {
                impliedRepos.add( obj.getString( "key" ) );
                continue;
            }
            if ( !obj.has( "metadata" ) )
            {
                continue;
            }
            JSONObject meta = obj.getJSONObject( "metadata" );
            if ( meta.has( "implied_by_stores" ) || meta.has( "implied_stores" ) || ( meta.has( "origin" )
                    && meta.getString( "origin" ).contains( "implied-repos" ) ) )
            {
                impliedRepos.add( obj.getString( "key" ) );
            }
        }
        logger.info( "HTTP enabled remote repos: {}", migrateRepos.keySet().size() );

        // Get groups to filter obsolete impliedRepos
        HttpRequest gRequest = HttpRequest.newBuilder()
                                          .uri( URI.create(
                                                  route + "/api/admin/stores/query/groups/all?enabled=true" ) )
                                          .build();
        HttpResponse gRes = client.send( gRequest, HttpResponse.BodyHandlers.ofString() );
        JSONArray gArray = new JSONObject( (String) gRes.body() ).getJSONArray( "items" );
        for ( int i = 0; i < gArray.length(); i++ )
        {
            JSONObject obj = gArray.getJSONObject( i );
            if ( !obj.has( "constituents" ) )
            {
                continue;
            }
            JSONArray constituents = obj.getJSONArray( "constituents" );
            for ( int j = 0; j < constituents.length(); j++ )
            {
                impliedRepos.remove( constituents.get( j ) );
            }
        }
        logger.info( "Total enabled obsolete Implied remote repos (not contained in any group): {}",
                     impliedRepos.size() );

        // Remove impliedRepos
        List<String> httpImpliedRepos = new ArrayList<>();
        for ( String key : impliedRepos )
        {
            if ( migrateRepos.containsKey( key ) )
            {
                httpImpliedRepos.add( key );
                migrateRepos.remove( key );
            }
        }
        logger.info( "HTTP Implied repos (not contained in any group): {}", httpImpliedRepos.size() );
        logger.info( "Left HTTP remote repos which exclude the Implied repos: {}", migrateRepos.keySet().size() );

        // Validate the migrated remote ssl url usability
        Map<String, String> brewRemote = new HashMap<>();
        Map<String, String> nonBrewRemote = new HashMap<>();
        Map<String, String> deadRemote = new HashMap<>();
        int promoteTempNum = 0;
        int newcastleNum = 0;
        int indyNum = 0;
        int tempOther = 0;

        int p = 0;
        for ( String key : migrateRepos.keySet() )
        {
            p++;
            logger.debug( "Validate migration ssl url in progress: total: {}, proceed: {}",
                          migrateRepos.keySet().size(), p );

            String url = migrateRepos.get( key );
            if ( key.contains( "Promote_tmp" ) )
            {
                promoteTempNum++;
                if ( url.contains( "indy.newcastle-stage.svc.cluster.local" ) )
                {
                    newcastleNum++;
                }
                else if ( url.contains( "indy-stage.psi.redhat.com" ) )
                {
                    indyNum++;
                }
                else
                {
                    tempOther++;
                }
                continue;
            }

            if ( migrateRepos.get( key ).startsWith( "http://download.eng.bos.redhat.com/brewroot" ) )
            {
                brewRemote.put( key, String.valueOf( 200 ) );
                continue;
            }

            String sslUrl = migrateRepos.get( key ).replace( "http://", "https://" );
            try
            {
                HttpRequest httpRequest = HttpRequest.newBuilder().uri( URI.create( sslUrl ) ).build();
                HttpResponse httpResponse = client.send( httpRequest, HttpResponse.BodyHandlers.ofString() );
                if ( httpResponse.statusCode() == 404 )
                {
                    deadRemote.put( key, "404" );
                }
                else
                {
                    nonBrewRemote.put( key, String.valueOf( httpResponse.statusCode() ) );
                }
            }
            catch ( IllegalArgumentException e )
            {
                nonBrewRemote.put( key, "IllegalArgumentException: " + e.getMessage() );
            }
            catch ( ConnectException e )
            {
                if ( null == e.getMessage() )
                {
                    deadRemote.put( key, "ConnectException: " + e.getMessage() );
                }
                else
                {
                    nonBrewRemote.put( key, "ConnectException: " + e.getMessage() );
                }
            }
            catch ( IOException e )
            {
                nonBrewRemote.put( key, "IOException: " + e.getMessage() );
            }
            catch ( Exception e )
            {
                nonBrewRemote.put( key, "Exception: " + e.getMessage() );
            }
        }
        logger.info( "Promote_tmp_* remote repos:{}, newcastleNum:{}, indyNum:{}, tempOther:{}", promoteTempNum,
                     newcastleNum, indyNum, tempOther );
        logger.info( "Dead remote repos (404 or URL could not be retrieved): {}", deadRemote.keySet().size() );
        logger.info( "Brew remote repos (http://download.eng.bos.redhat.com/brewroot/*): {}",
                     brewRemote.keySet().size() );
        logger.info( "Non-Brew remote repos: {}", nonBrewRemote.keySet().size() );

        // Do migration: update url metadata
        logger.info( "Start doing brewRemote ssl migration..." );
        for ( String key : brewRemote.keySet() )
        {
            String keyPath = key.replace( ":", "/" );
            HttpRequest getReq =
                    HttpRequest.newBuilder().uri( URI.create( route + "/api/admin/stores/" + keyPath ) ).build();
            HttpResponse getResp = client.send( getReq, HttpResponse.BodyHandlers.ofString() );

            JSONObject body = new JSONObject( (String) getResp.body() );
            body.put( "url", body.getString( "url" ).replace( "http://", "https://" ) );

            // Handle migration
            HttpRequest putReq = HttpRequest.newBuilder()
                                            .uri( URI.create( route + "/api/admin/stores/" + keyPath ) )
                                            .PUT( HttpRequest.BodyPublishers.ofString( body.toString() ) )
                                            .header( "Content-Type", "application/json" )
                                            .header( "Authorization", "Bearer " + token )
                                            .build();
            HttpResponse putResp = client.send( putReq, HttpResponse.BodyHandlers.ofString() );
            logger.info( "brewRemote: {}, response statusCode: {}.", key, putResp.statusCode() );
        }

        logger.info( "Start doing nonBrewRemote ssl migration..." );
        for ( String key : nonBrewRemote.keySet() )
        {
            String keyPath = key.replace( ":", "/" );
            HttpRequest getReq =
                    HttpRequest.newBuilder().uri( URI.create( route + "/api/admin/stores/" + keyPath ) ).build();
            HttpResponse getResp = client.send( getReq, HttpResponse.BodyHandlers.ofString() );

            JSONObject body = new JSONObject( (String) getResp.body() );
            body.put( "url", body.getString( "url" ).replace( "http://", "https://" ) );

            // Handle migration
            HttpRequest putReq = HttpRequest.newBuilder()
                                            .uri( URI.create( route + "/api/admin/stores/" + keyPath ) )
                                            .PUT( HttpRequest.BodyPublishers.ofString( body.toString() ) )
                                            .header( "Content-Type", "application/json" )
                                            .header( "Authorization", "Bearer " + token )
                                            .build();
            HttpResponse putResp = client.send( putReq, HttpResponse.BodyHandlers.ofString() );
            logger.info( "nonBrewRemote: {}, response statusCode: {}.", key, putResp.statusCode() );
        }
    }
}
