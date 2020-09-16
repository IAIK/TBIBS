// Copyright (C) 2002 IAIK
// http://jce.iaik.at
//
// Copyright (C) 2003 - 2014 Stiftung Secure Information and
//                           Communication Technologies SIC
// http://www.sic.st
//
// All rights reserved.
//
// This source is provided for inspection purposes and recompilation only,
// unless specified differently in a contract with IAIK. This source has to
// be kept in strict confidence and must not be disclosed to any third party
// under any circumstances. Redistribution in source and binary forms, with
// or without modification, are <not> permitted in any case!
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
// OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
// SUCH DAMAGE.
//
// $Header: $
// $Revision: $

package iaik.security.hibe;


  
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import iaik.asn1.structures.AlgorithmID;
   
/**
 * JCA provider for the MOA Key- and Crypto-Modules.
 */
public final class HIBEProvider extends Provider {
  
  /**
   * AlgorithmID (1.3.6.1.4.1.2706.5.3) for the HIBE signature scheme.
   */
  public static final AlgorithmID HIBE_ALG = new AlgorithmID("1.3.6.1.4.1.2706.5.3", "HIBE", "HIBE", false);
    

  /**
   * 
   */
  private static final long serialVersionUID = 2589346769223400822L;

  private final static double version = 1.00;
  
  private final static String name = "IAIK-HIBE";
  
  private final static String info = name  + " v" + version;
  
  
  
  /**
   * This is the default constructor which registers the implemented
   * algorithms to the Java Security API.
   */
  public HIBEProvider() {
      super(name, version, info);
       
    AccessController.doPrivileged((PrivilegedAction<Void>) () -> {
      addAlgorithms();
      return null;
    });
  }
 
  /**
   * Enter the algorithms.
   */
  private void addAlgorithms() {
    
    String algorithm = "HIBE";
    String oid = HIBE_ALG.getAlgorithm().getID();
    List<String> aliases = Arrays.asList(oid);
    Map<String,String> supportedAttributes = null;
    
    String type = "KeyFactory";
    String className = "iaik.security.hibe.HIBEKeyFactory"; 
    putService(new Service(this, type, algorithm, className, aliases, supportedAttributes));
    
    type = "KeyPairGenerator";
    className = "iaik.security.hibe.HIBEKeyPairGenerator";
    putService(new Service(this, type, algorithm, className, aliases, supportedAttributes));
    
    type = "Signature";
    oid = oid+".1";
    className = "iaik.security.hibe.HIBEWithSHA256Signature";
    putService(new Service(this, type, algorithm, className, aliases, supportedAttributes));
    
        
  }    
 
}


