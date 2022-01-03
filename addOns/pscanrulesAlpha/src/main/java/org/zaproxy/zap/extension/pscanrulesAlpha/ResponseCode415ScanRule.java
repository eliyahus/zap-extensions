/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.pscanrulesAlpha;

import java.util.Map;
import net.htmlparser.jericho.Source;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

public class ResponseCode415ScanRule extends PluginPassiveScanner {
    private static final Logger logger = LogManager.getLogger(ResponseCode415ScanRule.class);

    private static final String MESSAGE_PREFIX = "pscanalpha.responsecode415.";

    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG,
                    CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG);

    private static final int PLUGIN_ID = 90005;

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        if (msg.getResponseHeader().getStatusCode() == HttpStatusCode.UNSUPPORTED_MEDIA_TYPE) {
            logger.debug("Got response code 415, raising alert");
            raiseAlert();
            logger.debug("Alert for response code 415 was raised");
        }
    }

    private void raiseAlert() {
        newAlert()
                .setName(getName())
                .setRisk(getRisk())
                .setConfidence(getConfidence())
                .setDescription(getDescription())
                .setSolution(getSolution())
                .setReference(getReference())
                .setCweId(getCweId())
                .setWascId(getWascId())
                .raise();
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    @Override
    public int getPluginId() {
        return PLUGIN_ID;
    }

    public int getRisk() {
        return Alert.RISK_HIGH;
    }

    public int getConfidence() {
        return Alert.CONFIDENCE_HIGH;
    }

    public String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    public String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    public String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    public int getCweId() {
        return 345; // CWE Id 345 - Insufficient Verification of Data Authenticity
    }

    public int getWascId() {
        return 12; // WASC Id 12 - Content Spoofing
    }
}
