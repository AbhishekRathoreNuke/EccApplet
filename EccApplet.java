import javacard.framework.*;
import javacard.security.*;

public class EccApplet extends Applet {

    byte[] baTemp = new byte[255];
    byte[] baSignature = new byte[255];
    byte[] baText = new byte[255];
    byte[] baPrivKey = { (byte) 0x33, (byte) 0x4a, (byte) 0x6a, (byte) 0xa1, (byte) 0xd5, (byte) 0x42, (byte) 0xc3, (byte) 0x12, (byte) 0xbd, (byte) 0xfa, (byte) 0x70, (byte) 0x61, (byte) 0x99,
	    (byte) 0xb4, (byte) 0x11, (byte) 0xf7, (byte) 0xa8, (byte) 0xdd, (byte) 0xcf, (byte) 0xaf, (byte) 0x56, (byte) 0x3a, (byte) 0x7c, (byte) 0xb8 };
    byte[] baPubKey = { (byte) 0x04, (byte) 0x4e, (byte) 0x0d, (byte) 0xb7, (byte) 0xd8, (byte) 0x81, (byte) 0x39, (byte) 0xee, (byte) 0x2a, (byte) 0x4c, (byte) 0xd4, (byte) 0x75, (byte) 0x47,
	    (byte) 0x6b, (byte) 0x62, (byte) 0x9c, (byte) 0x10, (byte) 0x41, (byte) 0x9e, (byte) 0x3d, (byte) 0xa8, (byte) 0x35, (byte) 0x44, (byte) 0x5f, (byte) 0x50, (byte) 0x4c, (byte) 0x55,
	    (byte) 0x54, (byte) 0x40, (byte) 0xc4, (byte) 0x16, (byte) 0xfa, (byte) 0x2d, (byte) 0xde, (byte) 0xd7, (byte) 0x67, (byte) 0xf5, (byte) 0xea, (byte) 0x0d, (byte) 0xbc, (byte) 0x98,
	    (byte) 0x49, (byte) 0x7e, (byte) 0x95, (byte) 0x47, (byte) 0xb0, (byte) 0xb8, (byte) 0x09, (byte) 0x63 };

    short len, lenText, lenSignature;
    boolean result = false;

    KeyPair kp;
    ECPublicKey pubKey;
    ECPrivateKey privKey;
    Signature ecdsa;

    public static void install(byte[] bArray, short bOffset, byte bLength) {
	new EccApplet();
    }

    protected EccApplet() {
	register();
    }

    public void process(APDU apdu) {
	byte[] buffer = apdu.getBuffer();

	if (selectingApplet())
	    return;

	if (buffer[ISO7816.OFFSET_CLA] != (byte) 0x00)
	    ISOException.throwIt((short) 0x6660);

	switch (buffer[ISO7816.OFFSET_INS]) {
	case (byte) 0xD1:
	    processINSD1(apdu);
	    return;
	case (byte) 0xD2:
	    processINSD2(apdu);
	    return;
	case (byte) 0xD3:
	    processINSD3(apdu);
	    return;
	case (byte) 0xD4:
	    processINSD4(apdu);
	    return;
	default:
	    ISOException.throwIt((short) 0x6661);
	}
    }

    //////////////////////////////////////////
    // INS D1 - KEY PAIR GENERATION //
    // Generates a new key pair of 192 bits //
    // APDU EXAMPLE: 00D1000000 //
    //////////////////////////////////////////

    private void processINSD1(APDU apdu) {
	try {
	    kp = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_192);
	    kp.genKeyPair();
	    privKey = (ECPrivateKey) kp.getPrivate();
	    privKey.setS(baPrivKey, (short) 0, (short) baPrivKey.length);
	    pubKey = (ECPublicKey) kp.getPublic();
	    pubKey.setW(baPubKey, (short) 0, (short) baPubKey.length);
	    ecdsa = Signature.getInstance(Signature.ALG_ECDSA_SHA, false);
	} catch (Exception exception) {
	    ISOException.throwIt((short) 0xFFD1);
	}
    }

    //////////////////////////////////////////////
    // INS D2 - SIGNATURE //
    // DATA: string to be signed //
    // APDU EXAMPLE: 00D20000080102030405060708 //
    //////////////////////////////////////////////

    private void processINSD2(APDU apdu) {
	byte buffer[] = apdu.getBuffer();
	short numBytesInput = apdu.setIncomingAndReceive();
	lenText = 0;

	while (numBytesInput > 0) {
	    Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, baText, lenText, numBytesInput);
	    lenText += numBytesInput;
	    numBytesInput = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
	}

	try {
	    ecdsa.init(privKey, Signature.MODE_SIGN);
	    len = ecdsa.sign(baText, (short) 0, lenText, baSignature, (short) 0);

	    apdu.setOutgoing();
	    apdu.setOutgoingLength((short) len);
	    apdu.sendBytesLong(baSignature, (short) 0, len);
	} catch (Exception exception) {
	    ISOException.throwIt((short) 0xFFD2);
	}
    }

    ///////////////////////////////////////////////
    // INS D3 - INIT LOAD + SIGNATURE => Verify in next command i.e. processINSD4 //
    // P1: operation //
    // Values P1: 01: text load //
    // 02: signature load //
    // APDU EXAMPLE: 00D301000401020304 //
    // APDU EXAMPLE: 00D3020006010203040506 //
    ///////////////////////////////////////////////

    private void processINSD3(APDU apdu) {

	byte buffer[] = apdu.getBuffer();
	short numBytesInput = apdu.setIncomingAndReceive();

	if (buffer[2] == (byte) 0x01) // Text load
	{
	    lenText = 0;
	    while (numBytesInput > 0) {
		Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, baText, lenText, numBytesInput);
		lenText += numBytesInput;
		numBytesInput = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
		return;
	    }
	}

	if (buffer[2] == (byte) 0x02) // Signature load
	{
	    lenSignature = 0;
	    while (numBytesInput > 0) {
		Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, baSignature, lenSignature, numBytesInput);
		lenSignature += numBytesInput;
		numBytesInput = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
		return;
	    }
	}
	ISOException.throwIt((short) 0xFFD3);

    }

    /////////////////////////////////////
    // INS D4 - SIGNATURE VERIFICATION //
    // APDU EXAMPLE: 00D4000000 //
    /////////////////////////////////////

    private void processINSD4(APDU apdu) {
	try {
	    ecdsa.init(pubKey, Signature.MODE_VERIFY);
	    result = ecdsa.verify(baText, (short) 0, lenText, baSignature, (short) 0, lenSignature);
	} catch (Exception exception) {
	    ISOException.throwIt((short) 0xFFD4);
	}

	if (result)
	    return;
	else
	    ISOException.throwIt((short) 0xFFD5);
    }
}