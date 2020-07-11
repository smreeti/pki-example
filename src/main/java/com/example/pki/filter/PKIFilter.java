package com.example.pki.filter;

import com.example.pki.dto.pki.PKIData;
import com.example.pki.dto.pki.PKIErrorResponseDTO;
import com.example.pki.exception.BadRequestException;
import com.example.pki.utils.JacksonUtil;
import com.example.pki.wrapper.BufferedServletResponseWrapper;
import com.example.pki.wrapper.DataWrapper;
import com.example.pki.wrapper.RequestWrapper;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.OutputStream;
import java.rmi.server.ExportException;

import static com.example.pki.constants.ErrorMessageConstants.PKIMessages.MISSING_PAYLOAD;
import static com.example.pki.utils.SecurityUtil.encryptPayloadAndGenerateSignature;
import static com.example.pki.utils.SecurityUtil.responseValidator;

/**
 * @author smriti on 06/07/20
 */
@Slf4j
@Component
public class PKIFilter extends OncePerRequestFilter implements javax.servlet.Filter {

    private final DataWrapper dataWrapper;

    private static String serverPublicKey =
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAl0wB6IGgyzoJ9xkcsS2U2wJqDTBl/FyoHpVNxBbfC8twLzBoQvvSHUfeHHpMv1XLchoswegXBssIvFVFtbGtECY5bc8RsFHkwd1dFNYaweGvjVQslJMFesr4mH4ytBvJBmNVF2Hs+G8BEszeLQTRdOKbw7FE2cuo2vIuhVCmQLq0osHkZthaYC059+IqZ6VcTNPdlGcipxVvF/ZjZtjX89cTdBlFfBjzVmIbLDSjbvxQY6Wk1F5aweRdnzGpoOuoflkOoShOttQZa0ffHEV+86vPZnpe8cWDxd/ioDsuRNTqXWxl+ElTu4Ma2QZLse4LLue3tj+1xWxRcsem8R4j0QIDAQAB";

    private static String serverPrivateKey =
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCXTAHogaDLOgn3GRyxLZTbAmoNMGX8XKgelU3EFt8Ly3AvMGhC+9IdR94ceky/VctyGizB6BcGywi8VUW1sa0QJjltzxGwUeTB3V0U1hrB4a+NVCyUkwV6yviYfjK0G8kGY1UXYez4bwESzN4tBNF04pvDsUTZy6ja8i6FUKZAurSiweRm2FpgLTn34ipnpVxM092UZyKnFW8X9mNm2Nfz1xN0GUV8GPNWYhssNKNu/FBjpaTUXlrB5F2fMamg66h+WQ6hKE621BlrR98cRX7zq89mel7xxYPF3+KgOy5E1OpdbGX4SVO7gxrZBkux7gsu57e2P7XFbFFyx6bxHiPRAgMBAAECggEAcNJ+LcrUhBfwrHHugnUyJqtDODiaJLlXqQ6/YfWIOHxpWNcpOKIeijU4fVX5+0hYIOtB6wtOeINZLVANXrNzEbLfanJah3haNPME4W/TnjbUuXhGkjicgnfvL5AT8Vky6++Q2ZHtq0jjrQhWuY15QEdnzmNXq24CqdqlNEby4xrtjYnwruj3taClJMVpibjQ26syCWgpKGMqdWKEfry2Q+Xy6GdY2DRruh6YQthC1iIQOS23FqJeBrbo4+5gqDzjO5/yTBsGx3E9VS6eQM8sBYXcJFt9TEpreYMuuncpGeyi3veeoLNmaxZK3LG/IIDm6a0miS8I7CQ8xv6Jep90AQKBgQDpx8FrcrTpJgXBqYpUoSN56iE8E24EuXA43C5FfsTr12umqykamKo463tZPw7vvSTNl5ydlg7Jr7tAq9i3L+IPEV7/r3lZIEAOk0nBcTY5FIGs6refDTwx8l/0LTKqbKrdCD5jAvjGiXLF1yWVKN9Yny5Y5ePOK6C5zDE55FAdEQKBgQClrUzt43owsZRyxbBtsKlw1oltmDLYVGMlwEIIfxH2kus8GTaltR1AmTogxLMkdQP0s8A8Wj0qmBKEaE5uRBsdGQBAHDzOrQDWXqHmH92oJhIRCfCo4HpsVmPz2LwssdZPCzZv1DlrLkyKhuPncaMMdS/H1EY1CY7zAVAe23yawQKBgQDWcy1UuVaHASAKtNF2LJL0hPeTumcT4l+1aRTxHwbZKTVRIHWGNkEAEdOG3LeA58rY5Zj/XeWW0aM+AeW8tSnzlIXGmlsAjPr149qmnomU9uC1lGJ4fpWXY7TtsoBloWVjeOpxvQokZXVpUqDhISswimTjm47LU24OwebuKifrYQKBgBI+mFcmEsGj/JX7ASfDKZWcenvQI+FAwb5ZgqwO2jqOCUuP9z2eST9g4E7VemjMXggnd0buJQg4wOlF10U7SMUWiLmGooeb85inySpfXfhzYM/xiUf/mFuv08f5mRdO6ivAL1l3RG9yJMmoexZ0pCDuErntvWF/0PcfsOQFBZ7BAoGATSOgJJ3fN1wRMGLgMluR/wQHBbtVzBj5RG9tcAxrdPbKW7AA1wmUsmsxBPiXD1CZ+K5n2I2U62lg1bl5WdUaYPj35+m7mbnAC8j2lJ3qOjBfvEScvzus3WcXF5LgTITFkTrS4bguQf5+NQ8Vx0AuPqyiZchnBcVP7yJjCiHjmnI=";

    private static String clientPrivateKey = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAIX6uimxQQZIz20/qjOkpvyGMexox7I7BF+oyMSf0+LX4ySuNgwS48wKLxx1upG4kZcxT1GmErq0vzv7Gk0ywTatqWalcqzL/7jF2tAJTMVEyKJoL0zhr+pgkSJ7dZ1njxP6AHHG4OU4l7T287GwaMA78ekcCr89sqBCOeRt2UnnAgMBAAECgYBZOp3HbJyw0ccLrG3vTQZFgh43o6Tzx6hnCSMFCKj2F+/YGwo1ylLaLiIoIyQpLrIP7rAz4ZXxsLT3/okKxvW0NAuMm+Epj3DR/8waOuuTYZElhAmD6L7b4MV1V0t5k9qu3H4A3IhbtmQasvwEv1PFMwNQ8sBkXb+siIVazgeK0QJBAPJ8PAczoDvBpD+D6HQY4tPLIQZa5AT5ddVqF34wczSDm19R4h1GrRyfEZoHZ760fCDoYBkL8PvWSpUQl3xENqkCQQCNclZVydprAft9Ad1IiI8nd2bySlMcwbB7iwtoP0/ksgilxhonu6lMTsfEmr17Py5bzFTpECkFX0xC9cvG9SYPAkEAuqzDtbOb1oUTwkX1bXM/JFeLvA263s2BVmPPZDk+Z54tvesWzPz9Bjy7Wz36M0lVCix61q1nvyjQ0AMu697DyQJAGJ8eiDBq5NWjgU8hxc5/nM8cDHEDpq3QmrDJe4wJzDVxa+ngA6qW/cF45LBK63lECJa48RjvCxBbpgxDPI7P4QJAcW6RLuiu0o6969XOv541lI5+nW3IORhlL7gAdWdThPVJcB5tT+7e1Q3OcxJnCfrLtQWoCNnhRDGO2JtGS1xK0g==";
    private static String clientPublicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCF+ropsUEGSM9tP6ozpKb8hjHsaMeyOwRfqMjEn9Pi1+MkrjYMEuPMCi8cdbqRuJGXMU9RphK6tL87+xpNMsE2ralmpXKsy/+4xdrQCUzFRMiiaC9M4a/qYJEie3WdZ48T+gBxxuDlOJe09vOxsGjAO/HpHAq/PbKgQjnkbdlJ5wIDAQAB";

    private static String client_id = "test";

    public PKIFilter(DataWrapper dataWrapper) {
        this.dataWrapper = dataWrapper;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        BufferedServletResponseWrapper customResponse = new BufferedServletResponseWrapper(response);

        try (BufferedReader reader = request.getReader()) {
            String encryptedPayloadData = this.getPayloadData(reader);

            RequestWrapper requestWrapper = JacksonUtil.get(encryptedPayloadData, RequestWrapper.class);

            String decryptedData = responseValidator(requestWrapper, clientPublicKey, serverPrivateKey);

            dataWrapper.setData(decryptedData);

            filterChain.doFilter(request, response);

            if (!ObjectUtils.isEmpty(customResponse.getResponseData())) {
//                uri.startsWith(WebRoutes.CLIENT_REQUEST + "/")) {
                encryptResponse(response, customResponse, requestWrapper);
            }
        } catch (Exception e) {
            log.error("Error occurred while validating encrypted request :: {}", e.getMessage());
            handleFilterException(response, e);
        }
    }

    private void handleFilterException(HttpServletResponse httpServletResponse,
                                       Exception exception) throws IOException {


        PKIErrorResponseDTO errorResponseDTO = PKIErrorResponseDTO.builder()
                .status(400)
                .errorMessage(exception.getMessage())
                .build();

        String json = null;
        try {
            json = new ObjectMapper().writeValueAsString(errorResponseDTO);
        } catch (JsonProcessingException ex) {
            ex.printStackTrace();
        }
        assert json != null;
        httpServletResponse.getWriter().write(json);
        httpServletResponse.setStatus(errorResponseDTO.getStatus());
        httpServletResponse.flushBuffer();
    }

    private void encryptResponse(HttpServletResponse httpServletResponse,
                                 BufferedServletResponseWrapper customResponse,
                                 RequestWrapper requestWrapper) throws IOException {

        try {
            ObjectMapper objectMapper = new ObjectMapper();

            PKIData pkiData = encryptData(customResponse.getResponseData(), clientPublicKey);

            OutputStream outputStream = httpServletResponse.getOutputStream();
            outputStream.write(objectMapper.writeValueAsString(pkiData).getBytes());
            outputStream.flush();
            outputStream.close();
        } catch (ExportException e) {
            log.error("throw new error occurred while preparing encrypted response payload {}", e.getMessage());
            throw new BadRequestException(e.getMessage());
        }
    }

    private PKIData encryptData(String payload, String clientPublicKey) {
        log.info("Encrypting data with payload:{}", payload);

        return encryptPayloadAndGenerateSignature(payload, clientPublicKey, serverPrivateKey);
    }

    private String getPayloadData(BufferedReader reader) throws IOException {
        final StringBuilder builder = new StringBuilder();
        if (reader == null) {
            log.error("Request body is null");
            throw new BadRequestException(MISSING_PAYLOAD);
        }
        String line;
        while ((line = reader.readLine()) != null) {
            builder.append(line);
        }
        return builder.toString();
    }

    @Override
    public void destroy() {
    }

}
