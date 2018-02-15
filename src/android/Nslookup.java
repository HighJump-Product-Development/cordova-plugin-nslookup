
package org.tiste.cordova.nslookup;

import org.xbill.DNS.*;

import org.apache.cordova.CordovaWebView;
import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaInterface;

import java.net.InetAddress;
import java.util.concurrent.ExecutionException;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class Nslookup extends CordovaPlugin {
  public static final String TAG = "Nslookup";

  @Override
  public void initialize(CordovaInterface cordova, CordovaWebView webView) {
    super.initialize(cordova, webView);
  }

  @Override
  public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
    if ("getNsLookupInfo".equals(action)) {
      this.nsLookup(args, callbackContext);
      return true;
    }
    return false;
  }

  private void nsLookup(JSONArray args, CallbackContext callbackContext) {
    try {
      if (args != null && args.length() > 0) {
        JSONArray resultList = new JSONArray();
        int length = args.length();
        for (int index = 0; index < length; index++) {
          String query = "";
          String type = "";
          
          try {
            JSONObject obj = args.optJSONObject(index);
            query = obj.optString("query");
            type = obj.optString("type");
          } catch (Exception err) {
            try {
              query = args.getString(index);
              type = "";
            } catch (Exception e) {
            
            }
          }
          JSONObject result = doNslookup(query, type);
          resultList.put(result);
        }
        callbackContext.success(resultList);
      } else {
        callbackContext.error("Error occurred");
      }
    } catch (Exception e) {
      System.out.println(e.getMessage());
    }
  }

  private JSONObject doNslookup(String query, String type){
    System.out.println("doNslookup \n");
    System.out.println(query + "\n");
    JSONObject r = new JSONObject();
    try {
      r.put("query", query);
      r.put("type", type);
    } catch (JSONException e) {
    
    }
    if (type == "") {
      try {
        InetAddress addr = Address.getByName(query);
        r.put("result", addr.toString());
      } catch (Exception e) {
        System.out.println(e.getMessage());
      }
    } else {
      try {
        Record [] records;
        JSONArray recordArray = new JSONArray();
        if (type.equals("A")) {
          records = new Lookup(query, Type.A).run();
          if (records == null) {
            throw new Exception("Failed to get records.");
          }
          for (int i = 0; i < records.length; i++) {
            JSONObject obj = new JSONObject();
            ARecord rec = (ARecord) records[i];
            obj.put("address", rec.getAddress());
            recordArray.put(obj);
          }
        } else if (type.equals("AAAA")) {
          records = new Lookup(query, Type.AAAA).run();
          if (records == null) {
            throw new Exception("Failed to get records.");
          }
          for (int i = 0; i < records.length; i++) {
            JSONObject obj = new JSONObject();
            AAAARecord rec = (AAAARecord) records[i];
            obj.put("address", rec.getAddress());
            recordArray.put(obj);
          }
        } else if (type.equals("CNAME")) {
          records = new Lookup(query, Type.CNAME).run();
          if (records == null) {
            throw new Exception("Failed to get records.");
          }
          for (int i = 0; i < records.length; i++) {
            JSONObject obj = new JSONObject();
            CNAMERecord rec = (CNAMERecord) records[i];
            obj.put("target", rec.getTarget());
            obj.put("alias", rec.getAlias());
            recordArray.put(obj);
          }
        } else if (type.equals("MX")) {
          records = new Lookup(query, Type.MX).run();
          if (records == null) {
            throw new Exception("Failed to get records.");
          }
          for (int i = 0; i < records.length; i++) {
            JSONObject obj = new JSONObject();
            MXRecord rec = (MXRecord) records[i];
            obj.put("target", rec.getTarget());
            obj.put("priority", rec.getPriority());
            recordArray.put(obj);
          }
        } else if (type.equals("NS")) {
          records = new Lookup(query, Type.NS).run();
          if (records == null) {
            throw new Exception("Failed to get records.");
          }
          for (int i = 0; i < records.length; i++) {
            JSONObject obj = new JSONObject();
            NSRecord rec = (NSRecord) records[i];
            obj.put("target", rec.getTarget());
            recordArray.put(obj);
          }
        } else if (type.equals("PTR")) {
          records = new Lookup(query, Type.PTR).run();
          if (records == null) {
            throw new Exception("Failed to get records.");
          }
          for (int i = 0; i < records.length; i++) {
            JSONObject obj = new JSONObject();
            PTRRecord rec = (PTRRecord) records[i];
            obj.put("target", rec.getTarget());
            recordArray.put(obj);
          }
        } else if (type.equals("SOA")) {
          records = new Lookup(query, Type.SOA).run();
          if (records == null) {
            throw new Exception("Failed to get records.");
          }
          for (int i = 0; i < records.length; i++) {
            JSONObject obj = new JSONObject();
            SOARecord rec = (SOARecord) records[i];
            obj.put("host", rec.getHost());
            obj.put("admin", rec.getAdmin());
            obj.put("serial", rec.getSerial());
            obj.put("refresh", rec.getRefresh());
            obj.put("retry", rec.getRetry());
            obj.put("expire", rec.getExpire());
            obj.put("minimum", rec.getMinimum());
            recordArray.put(obj);
          }
        } else if (type.equals("SPF")) {
          records = new Lookup(query, Type.SPF).run();
          if (records == null) {
            throw new Exception("Failed to get records.");
          }
          for (int i = 0; i < records.length; i++) {
            JSONObject obj = new JSONObject();
            SPFRecord rec = (SPFRecord) records[i];
            obj.put("strings", rec.getStrings());
            recordArray.put(obj);
          }
        } else if (type.equals("SRV")) {
          records = new Lookup(query, Type.SRV).run();
          if (records == null) {
            throw new Exception("Failed to get records.");
          }
          for (int i = 0; i < records.length; i++) {
            JSONObject obj = new JSONObject();
            SRVRecord rec = (SRVRecord) records[i];
            obj.put("target", rec.getTarget());
            obj.put("port", rec.getPort());
            obj.put("priority", rec.getPriority());
            obj.put("weight", rec.getWeight());
            recordArray.put(obj);
          }
        } else if (type.equals("TXT")) {
          records = new Lookup(query, Type.TXT).run();
          if (records == null) {
            throw new Exception("Failed to get records.");
          }
          for (int i = 0; i < records.length; i++) {
            JSONObject obj = new JSONObject();
            TXTRecord rec = (TXTRecord) records[i];
            obj.put("strings", rec.getStrings());
            recordArray.put(obj);
          }
        }
        r.put("result", recordArray);
      } catch (Exception e) {
        System.out.println(e.getMessage());
      }
    }
    return r;
  }
}
