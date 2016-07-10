/*
 * See licence in the LICENSE file.
 * A burpsuite extension to deal with weird applications that do
 * everything via XML requests and require a token and another 
 * request to get the result of an injection.
 */
package burp;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

/**
 * @author me
 */
public class BurpExtender implements IBurpExtender, ISessionHandlingAction {
    
    private static final String TOKEN_NAME = "Token";
    private static final String TOKEN_PARAM = "3";
    private static final String RESPONSE_PARAM = "128";
    private static final String EQUAL = "=";
    private static final String TOKEN_URL = "/xml/getter.xml";
    private static final String HTTP_VERSION = "HTTP/1.1";
    private static final String POST_METHOD = "POST";
    
    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;
    private IHttpService httpService;
    private String target;
    private int port;

    private PrintWriter stdout;
    private PrintWriter stderr;

    /**
     * Extract the token from the XML response.
     */
    private String parseToken(byte[] tokenResponse)
            throws SAXException, IOException {
        try {
            // Parse the xml response to get the token.
            // Why to people still use XML?
            IResponseInfo response = helpers.analyzeResponse(tokenResponse);
            byte[] xml = Arrays.copyOfRange(tokenResponse,
                    response.getBodyOffset(),
                    tokenResponse.length);
            DocumentBuilderFactory dbFactory
                    = DocumentBuilderFactory.newInstance();
            DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
            Document doc = dBuilder.parse(new ByteArrayInputStream(xml));
            doc.getDocumentElement().normalize();
            // This is where we get the token from the XML.
            String token = doc.getFirstChild().getFirstChild().getTextContent();
            stdout.println("Token:" + token);
            return token;
        } catch (ParserConfigurationException ex) {
            stderr.println(ex);
        }
        return null;
    }
    
    /**
     * Build the /xml/getter.xml request with the right fun parameter based on
     * the actual message.
     */
    private byte[] getGetterRequest(IHttpRequestResponse message, String fun) {
        IParameter tokenParam = helpers.buildParameter(
                "fun", fun, IParameter.PARAM_BODY);
        List<String> newHeaders = new LinkedList<>();
        for (String header : helpers.analyzeRequest(message).getHeaders()) {
            // We just change the file requested.
            if (header.startsWith(POST_METHOD)) {
                newHeaders.add(
                        POST_METHOD + " " + TOKEN_URL + " " + HTTP_VERSION);
            } else {
                newHeaders.add(header);
            }
        }
        byte[] requestToken = helpers.buildHttpMessage(newHeaders,
                helpers.stringToBytes(
                        // Add the right parameter to request the token.
                        tokenParam.getName() + EQUAL + tokenParam.getValue()));
        return requestToken;
    }
    
    /**
     * Get the token corresponding tho the message.
     */
    private byte[] getTokenResponse(IHttpRequestResponse message) {
        byte[] requestToken = getGetterRequest(message, TOKEN_PARAM);
        return callbacks.makeHttpRequest(target, port, false, requestToken);
    }
    
    /**
     * Build the request to get the output of the command.
     */
    private byte[] getCommandRequest(IHttpRequestResponse message) {
        return getGetterRequest(message, RESPONSE_PARAM);
    }
    
    @Override
    public void performAction(IHttpRequestResponse currentRequest,
            IHttpRequestResponse[] macroItems) {
        try {
            httpService = currentRequest.getHttpService();
            target = httpService.getHost();
            port = httpService.getPort();
            byte[] tokenResponse = getTokenResponse(currentRequest);
            if (tokenResponse == null) {
                stderr.println("Could not get token.");
            } else{
                byte[] requestMessage = currentRequest.getRequest();
                String token = parseToken(tokenResponse);
                IParameter tokenParam = helpers.buildParameter(
                        TOKEN_NAME.toLowerCase(), token, IParameter.PARAM_BODY);
                // Change the token in the setter request
                // Remove the SID. Why is it here???
                for (IParameter param : helpers.analyzeRequest(
                        currentRequest).getParameters()) {
                    IParameter toRemove = helpers.buildParameter(
                            param.getName(),
                            param.getValue(),
                            IParameter.PARAM_BODY);
                    requestMessage = helpers.removeParameter(
                            requestMessage, toRemove);
                    if (param.getName().toUpperCase().equals(
                            "SID".toUpperCase())) {
                        continue;
                    }
                    if (param.getName().equals(TOKEN_NAME.toLowerCase())) {
                        requestMessage = helpers.addParameter(
                                requestMessage, tokenParam);
                    } else {
                        requestMessage = helpers.addParameter(
                                requestMessage, toRemove);
                    }
                }
                stdout.println("Sending original request ...");
                byte[] originalResponse = callbacks.makeHttpRequest(
                        target, port, false, requestMessage);
                if (originalResponse == null) {
                    stderr.println("No answer to original request.");
                } else {
                    stdout.println("Getting response: ...");
                    currentRequest.setRequest(
                            getCommandRequest(currentRequest));
                }
            }
        } catch (SAXException | IOException ex) {
            stderr.println(ex);
        }
    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
        
        callbacks.setExtensionName("3stepRequest");
        callbacks.registerSessionHandlingAction(this);
        stdout.println("3 step request loaded.");
    }

    @Override
    public String getActionName() {
        return "3 step request with token";
    }
}
