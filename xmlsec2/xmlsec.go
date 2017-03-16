package xmlsec2

import (
	"errors"
	"io/ioutil"
	"strings"
	"github.com/crewjam/go-xmlsec"
)

var xmlResponseID = xmlsec.XMLIDOption{
		ElementNamespace: "urn:oasis:names:tc:SAML:2.0:protocol",
		ElementName: "Response",
		AttributeName: "ID",
	}
var xmlRequestID = xmlsec.XMLIDOption{
		ElementNamespace: "urn:oasis:names:tc:SAML:2.0:protocol",
		ElementName: "AuthnRequest",
		AttributeName: "ID",
	}

// SignRequest sign a SAML 2.0 AuthnRequest
// `privateKeyPath` must be a path on the filesystem, xmlsec1 is run out of process
// through `exec`
func SignRequest(xml string, privateKeyPath string) (string, error) {
	return sign(xml, privateKeyPath, xmlRequestID)
}

// SignResponse sign a SAML 2.0 Response
// `privateKeyPath` must be a path on the filesystem, xmlsec1 is run out of process
// through `exec`
func SignResponse(xml string, privateKeyPath string) (string, error) {
	return sign(xml, privateKeyPath, xmlResponseID)
}

func sign(xml string, privateKeyPath string, id xmlsec.XMLIDOption) (string, error) {

	privateKey, privErr := ioutil.ReadFile(privateKeyPath)
	if privErr != nil {
		return "", errors.New("Error signing XML document. Details: " + privErr.Error())
	}

	xmlDoc := "<?xml version='1.0' encoding='UTF-8'?>\n" + xml

	signedDoc, signErr := xmlsec.Sign(privateKey, []byte(xmlDoc), xmlsec.SignatureOptions{
		XMLID: []xmlsec.XMLIDOption{id},
	})
	if signErr != nil {
		return "", errors.New("Error signing XML document. Details: " + signErr.Error())
	}

	samlSignedRequestXML := strings.Trim(string(signedDoc), "\n")
	return samlSignedRequestXML, nil
}

// VerifyResponseSignature verify signature of a SAML 2.0 Response document
// `publicCertPath` must be a path on the filesystem, xmlsec1 is run out of process
// through `exec`
func VerifyResponseSignature(xml string, publicCertPath string) error {
	return verify(xml, publicCertPath, xmlResponseID)
}

// VerifyRequestSignature verify signature of a SAML 2.0 AuthnRequest document
// `publicCertPath` must be a path on the filesystem, xmlsec1 is run out of process
// through `exec`
func VerifyRequestSignature(xml string, publicCertPath string) error {
	return verify(xml, publicCertPath, xmlRequestID)
}

func verify(xmlDoc string, publicCertPath string, id xmlsec.XMLIDOption) error {

	cert, certErr := ioutil.ReadFile(publicCertPath)
	if certErr != nil {
		return errors.New("Error veryfying XML document signature. Details: " + certErr.Error())
	}
	err := xmlsec.Verify(cert, []byte(xmlDoc), xmlsec.SignatureOptions{
		XMLID: []xmlsec.XMLIDOption{id},
	})
	if err == xmlsec.ErrVerificationFailed {
		return errors.New("error verifing signature: " + err.Error())
	}
	return nil
}
