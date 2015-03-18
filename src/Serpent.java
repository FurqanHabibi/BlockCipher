
public class Serpent {

	private int ROUNDS = 32;
    private int PHI    = 0x9E3779B9;       // (sqrt(5) - 1) * 2**31
    private int[] wKey;
    private int X0, X1, X2, X3;    // registers
    
    public Serpent() {
    	
    }
	
    public Serpent(byte[] key) {
    	wKey = makeWorkingKey(key);
    }
    
    public void encryptRound( byte[] in, int inOff, byte[] out, int outOff, int round) {
        X3 = bytesToWord(in, inOff);
        X2 = bytesToWord(in, inOff + 4);
        X1 = bytesToWord(in, inOff + 8);
        X0 = bytesToWord(in, inOff + 12);
        
        switch (round%8) {
        case 0 :
        	sb0(wKey[(round*4)] ^ X0, wKey[(round*4)+1] ^ X1, wKey[(round*4)+2] ^ X2, wKey[(round*4)+3] ^ X3);
        	break;
        case 1 :
        	sb1(wKey[(round*4)] ^ X0, wKey[(round*4)+1] ^ X1, wKey[(round*4)+2] ^ X2, wKey[(round*4)+3] ^ X3);
        	break;
        case 2 :
        	sb2(wKey[(round*4)] ^ X0, wKey[(round*4)+1] ^ X1, wKey[(round*4)+2] ^ X2, wKey[(round*4)+3] ^ X3);
        	break;
        case 3 :
        	sb3(wKey[(round*4)] ^ X0, wKey[(round*4)+1] ^ X1, wKey[(round*4)+2] ^ X2, wKey[(round*4)+3] ^ X3);
        	break;
        case 4 :
        	sb4(wKey[(round*4)] ^ X0, wKey[(round*4)+1] ^ X1, wKey[(round*4)+2] ^ X2, wKey[(round*4)+3] ^ X3);
        	break;
        case 5 :
        	sb5(wKey[(round*4)] ^ X0, wKey[(round*4)+1] ^ X1, wKey[(round*4)+2] ^ X2, wKey[(round*4)+3] ^ X3);
        	break;
        case 6 :
        	sb6(wKey[(round*4)] ^ X0, wKey[(round*4)+1] ^ X1, wKey[(round*4)+2] ^ X2, wKey[(round*4)+3] ^ X3);
        	break;
        case 7 :
        	sb7(wKey[(round*4)] ^ X0, wKey[(round*4)+1] ^ X1, wKey[(round*4)+2] ^ X2, wKey[(round*4)+3] ^ X3);
        	break;
        }
        LT();

        wordToBytes(X3, out, outOff);
        wordToBytes(X2, out, outOff + 4);
        wordToBytes(X1, out, outOff + 8);
        wordToBytes(X0, out, outOff + 12);
    }
    
    public void decryptRound( byte[] in, int inOff, byte[] out, int outOff, int round) {
        X3 = bytesToWord(in, inOff);
        X2 = bytesToWord(in, inOff + 4);
        X1 = bytesToWord(in, inOff + 8);
        X0 = bytesToWord(in, inOff + 12);
        
        inverseLT();
        switch (round%8) {
        case 0 :
        	ib0(X0, X1, X2, X3);
        	X0 ^= wKey[(round*4)]; X1 ^= wKey[(round*4)+1]; X2 ^= wKey[(round*4)+2]; X3 ^= wKey[(round*4)+3];
        	break;
        case 1 :
        	ib1(X0, X1, X2, X3);
        	X0 ^= wKey[(round*4)]; X1 ^= wKey[(round*4)+1]; X2 ^= wKey[(round*4)+2]; X3 ^= wKey[(round*4)+3];
        	break;
        case 2 :
        	ib2(X0, X1, X2, X3);
        	X0 ^= wKey[(round*4)]; X1 ^= wKey[(round*4)+1]; X2 ^= wKey[(round*4)+2]; X3 ^= wKey[(round*4)+3];
        	break;
        case 3 :
        	ib3(X0, X1, X2, X3);
        	X0 ^= wKey[(round*4)]; X1 ^= wKey[(round*4)+1]; X2 ^= wKey[(round*4)+2]; X3 ^= wKey[(round*4)+3];
        	break;
        case 4 :
        	ib4(X0, X1, X2, X3);
        	X0 ^= wKey[(round*4)]; X1 ^= wKey[(round*4)+1]; X2 ^= wKey[(round*4)+2]; X3 ^= wKey[(round*4)+3];
        	break;
        case 5 :
        	ib5(X0, X1, X2, X3);
        	X0 ^= wKey[(round*4)]; X1 ^= wKey[(round*4)+1]; X2 ^= wKey[(round*4)+2]; X3 ^= wKey[(round*4)+3];
        	break;
        case 6 :
        	ib6(X0, X1, X2, X3);
        	X0 ^= wKey[(round*4)]; X1 ^= wKey[(round*4)+1]; X2 ^= wKey[(round*4)+2]; X3 ^= wKey[(round*4)+3];
        	break;
        case 7 :
        	ib7(X0, X1, X2, X3);
        	X0 ^= wKey[(round*4)]; X1 ^= wKey[(round*4)+1]; X2 ^= wKey[(round*4)+2]; X3 ^= wKey[(round*4)+3];
        	break;
        }

        wordToBytes(X3, out, outOff);
        wordToBytes(X2, out, outOff + 4);
        wordToBytes(X1, out, outOff + 8);
        wordToBytes(X0, out, outOff + 12);
    }
    
    private int[] makeWorkingKey(byte[] key) throws  IllegalArgumentException {
        //
        // pad key to 256 bits
        //
        int[]   kPad = new int[16];
        int     off = 0;
        int     length = 0;

        for (off = key.length - 4; off > 0; off -= 4)
        {
            kPad[length++] = bytesToWord(key, off);
        }

        if (off == 0)
        {
            kPad[length++] = bytesToWord(key, 0);
            if (length < 8)
            {
                kPad[length] = 1;
            }
        }
        else
        {
            throw new IllegalArgumentException("key must be a multiple of 4 bytes");
        }

        //
        // expand the padded key up to 33 x 128 bits of key material
        //
        int     amount = (ROUNDS + 1) * 4;
        int[]   w = new int[amount];

        //
        // compute w0 to w7 from w-8 to w-1
        //
        for (int i = 8; i < 16; i++)
        {
            kPad[i] = rotateLeft(kPad[i - 8] ^ kPad[i - 5] ^ kPad[i - 3] ^ kPad[i - 1] ^ PHI ^ (i - 8), 11);
        }

        System.arraycopy(kPad, 8, w, 0, 8);

        //
        // compute w8 to w136
        //
        for (int i = 8; i < amount; i++)
        {
            w[i] = rotateLeft(w[i - 8] ^ w[i - 5] ^ w[i - 3] ^ w[i - 1] ^ PHI ^ i, 11);
        }

        //
        // create the working keys by processing w with the Sbox and IP
        //
        sb3(w[0], w[1], w[2], w[3]);
        w[0] = X0; w[1] = X1; w[2] = X2; w[3] = X3; 
        sb2(w[4], w[5], w[6], w[7]);
        w[4] = X0; w[5] = X1; w[6] = X2; w[7] = X3; 
        sb1(w[8], w[9], w[10], w[11]);
        w[8] = X0; w[9] = X1; w[10] = X2; w[11] = X3; 
        sb0(w[12], w[13], w[14], w[15]);
        w[12] = X0; w[13] = X1; w[14] = X2; w[15] = X3; 
        sb7(w[16], w[17], w[18], w[19]);
        w[16] = X0; w[17] = X1; w[18] = X2; w[19] = X3; 
        sb6(w[20], w[21], w[22], w[23]);
        w[20] = X0; w[21] = X1; w[22] = X2; w[23] = X3; 
        sb5(w[24], w[25], w[26], w[27]);
        w[24] = X0; w[25] = X1; w[26] = X2; w[27] = X3; 
        sb4(w[28], w[29], w[30], w[31]);
        w[28] = X0; w[29] = X1; w[30] = X2; w[31] = X3; 
        sb3(w[32], w[33], w[34], w[35]);
        w[32] = X0; w[33] = X1; w[34] = X2; w[35] = X3; 
        sb2(w[36], w[37], w[38], w[39]);
        w[36] = X0; w[37] = X1; w[38] = X2; w[39] = X3; 
        sb1(w[40], w[41], w[42], w[43]);
        w[40] = X0; w[41] = X1; w[42] = X2; w[43] = X3; 
        sb0(w[44], w[45], w[46], w[47]);
        w[44] = X0; w[45] = X1; w[46] = X2; w[47] = X3; 
        sb7(w[48], w[49], w[50], w[51]);
        w[48] = X0; w[49] = X1; w[50] = X2; w[51] = X3; 
        sb6(w[52], w[53], w[54], w[55]);
        w[52] = X0; w[53] = X1; w[54] = X2; w[55] = X3; 
        sb5(w[56], w[57], w[58], w[59]);
        w[56] = X0; w[57] = X1; w[58] = X2; w[59] = X3; 
        sb4(w[60], w[61], w[62], w[63]);
        w[60] = X0; w[61] = X1; w[62] = X2; w[63] = X3; 
        sb3(w[64], w[65], w[66], w[67]);
        w[64] = X0; w[65] = X1; w[66] = X2; w[67] = X3; 
        sb2(w[68], w[69], w[70], w[71]);
        w[68] = X0; w[69] = X1; w[70] = X2; w[71] = X3; 
        sb1(w[72], w[73], w[74], w[75]);
        w[72] = X0; w[73] = X1; w[74] = X2; w[75] = X3; 
        sb0(w[76], w[77], w[78], w[79]);
        w[76] = X0; w[77] = X1; w[78] = X2; w[79] = X3; 
        sb7(w[80], w[81], w[82], w[83]);
        w[80] = X0; w[81] = X1; w[82] = X2; w[83] = X3; 
        sb6(w[84], w[85], w[86], w[87]);
        w[84] = X0; w[85] = X1; w[86] = X2; w[87] = X3; 
        sb5(w[88], w[89], w[90], w[91]);
        w[88] = X0; w[89] = X1; w[90] = X2; w[91] = X3; 
        sb4(w[92], w[93], w[94], w[95]);
        w[92] = X0; w[93] = X1; w[94] = X2; w[95] = X3; 
        sb3(w[96], w[97], w[98], w[99]);
        w[96] = X0; w[97] = X1; w[98] = X2; w[99] = X3; 
        sb2(w[100], w[101], w[102], w[103]);
        w[100] = X0; w[101] = X1; w[102] = X2; w[103] = X3; 
        sb1(w[104], w[105], w[106], w[107]);
        w[104] = X0; w[105] = X1; w[106] = X2; w[107] = X3; 
        sb0(w[108], w[109], w[110], w[111]);
        w[108] = X0; w[109] = X1; w[110] = X2; w[111] = X3; 
        sb7(w[112], w[113], w[114], w[115]);
        w[112] = X0; w[113] = X1; w[114] = X2; w[115] = X3; 
        sb6(w[116], w[117], w[118], w[119]);
        w[116] = X0; w[117] = X1; w[118] = X2; w[119] = X3; 
        sb5(w[120], w[121], w[122], w[123]);
        w[120] = X0; w[121] = X1; w[122] = X2; w[123] = X3; 
        sb4(w[124], w[125], w[126], w[127]);
        w[124] = X0; w[125] = X1; w[126] = X2; w[127] = X3; 
        sb3(w[128], w[129], w[130], w[131]);
        w[128] = X0; w[129] = X1; w[130] = X2; w[131] = X3; 

        return w;
    }

    private int rotateLeft(
        int     x,
        int     bits)
    {
        return (x << bits) | (x >>> -bits);
    }

    private int rotateRight(
        int     x,
        int     bits)
    {
        return (x >>> bits) | (x << -bits);
    }

    private int bytesToWord(
        byte[]  src,
        int     srcOff)
    {
        return (((src[srcOff] & 0xff) << 24) | ((src[srcOff + 1] & 0xff) <<  16) |
          ((src[srcOff + 2] & 0xff) << 8) | ((src[srcOff + 3] & 0xff)));
    }

    private void wordToBytes(
        int     word,
        byte[]  dst,
        int     dstOff)
    {
        dst[dstOff + 3] = (byte)(word);
        dst[dstOff + 2] = (byte)(word >>> 8);
        dst[dstOff + 1] = (byte)(word >>> 16);
        dst[dstOff]     = (byte)(word >>> 24);
    }

    /**
     * S0 - { 3, 8,15, 1,10, 6, 5,11,14,13, 4, 2, 7, 0, 9,12 } - 15 terms.
     */
    private void sb0(int a, int b, int c, int d)    
    {
        int    t1 = a ^ d;        
        int    t3 = c ^ t1;    
        int    t4 = b ^ t3;    
        X3 = (a & d) ^ t4;    
        int    t7 = a ^ (b & t1);    
        X2 = t4 ^ (c | t7);    
        int    t12 = X3 & (t3 ^ t7);    
        X1 = (~t3) ^ t12;    
        X0 = t12 ^ (~t7);
    }

    /**
     * InvSO - {13, 3,11, 0,10, 6, 5,12, 1,14, 4, 7,15, 9, 8, 2 } - 15 terms.
     */
    private void ib0(int a, int b, int c, int d)    
    {
        int    t1 = ~a;        
        int    t2 = a ^ b;        
        int    t4 = d ^ (t1 | t2);    
        int    t5 = c ^ t4;    
        X2 = t2 ^ t5;    
        int    t8 = t1 ^ (d & t2);    
        X1 = t4 ^ (X2 & t8);    
        X3 = (a & t4) ^ (t5 | X1);    
        X0 = X3 ^ (t5 ^ t8);
    }

    /**
     * S1 - {15,12, 2, 7, 9, 0, 5,10, 1,11,14, 8, 6,13, 3, 4 } - 14 terms.
     */
    private void sb1(int a, int b, int c, int d)    
    {
        int    t2 = b ^ (~a);    
        int    t5 = c ^ (a | t2);    
        X2 = d ^ t5;        
        int    t7 = b ^ (d | t2);    
        int    t8 = t2 ^ X2;    
        X3 = t8 ^ (t5 & t7);    
        int    t11 = t5 ^ t7;    
        X1 = X3 ^ t11;    
        X0 = t5 ^ (t8 & t11);
    }

    /**
     * InvS1 - { 5, 8, 2,14,15, 6,12, 3,11, 4, 7, 9, 1,13,10, 0 } - 14 steps.
     */
    private void ib1(int a, int b, int c, int d)    
    {
        int    t1 = b ^ d;        
        int    t3 = a ^ (b & t1);    
        int    t4 = t1 ^ t3;    
        X3 = c ^ t4;        
        int    t7 = b ^ (t1 & t3);    
        int    t8 = X3 | t7;    
        X1 = t3 ^ t8;    
        int    t10 = ~X1;        
        int    t11 = X3 ^ t7;    
        X0 = t10 ^ t11;    
        X2 = t4 ^ (t10 | t11);
    }

    /**
     * S2 - { 8, 6, 7, 9, 3,12,10,15,13, 1,14, 4, 0,11, 5, 2 } - 16 terms.
     */
    private void sb2(int a, int b, int c, int d)    
    {
        int    t1 = ~a;        
        int    t2 = b ^ d;
        int    t3 = c & t1;
        X0 = t2 ^ t3;
        int    t5 = c ^ t1;
        int    t6 = c ^ X0;
        int    t7 = b & t6;
        X3 = t5 ^ t7;
        X2 = a ^ ((d | t7) & (X0 | t5));
        X1 = (t2 ^ X3) ^ (X2 ^ (d | t1));
    }

    /**
     * InvS2 - {12, 9,15, 4,11,14, 1, 2, 0, 3, 6,13, 5, 8,10, 7 } - 16 steps.
     */
    private void ib2(int a, int b, int c, int d)    
    {
        int    t1 = b ^ d;        
        int    t2 = ~t1;        
        int    t3 = a ^ c;
        int    t4 = c ^ t1;
        int    t5 = b & t4;
        X0 = t3 ^ t5;
        int    t7 = a | t2;
        int    t8 = d ^ t7;
        int    t9 = t3 | t8;
        X3 = t1 ^ t9;
        int    t11 = ~t4;        
        int    t12 = X0 | X3;
        X1 = t11 ^ t12;
        X2 = (d & t11) ^ (t3 ^ t12);
    }

    /**
     * S3 - { 0,15,11, 8,12, 9, 6, 3,13, 1, 2, 4,10, 7, 5,14 } - 16 terms.
     */
    private void sb3(int a, int b, int c, int d)    
    {
        int    t1 = a ^ b;        
        int    t2 = a & c;        
        int    t3 = a | d;        
        int    t4 = c ^ d;        
        int    t5 = t1 & t3;    
        int    t6 = t2 | t5;    
        X2 = t4 ^ t6;    
        int    t8 = b ^ t3;    
        int    t9 = t6 ^ t8;    
        int    t10 = t4 & t9;    
        X0 = t1 ^ t10;    
        int    t12 = X2 & X0;    
        X1 = t9 ^ t12;    
        X3 = (b | d) ^ (t4 ^ t12);
    }

    /**
     * InvS3 - { 0, 9,10, 7,11,14, 6,13, 3, 5,12, 2, 4, 8,15, 1 } - 15 terms
     */
    private void ib3(int a, int b, int c, int d)    
    {
        int    t1 = a | b;        
        int    t2 = b ^ c;        
        int    t3 = b & t2;    
        int    t4 = a ^ t3;    
        int    t5 = c ^ t4;    
        int    t6 = d | t4;    
        X0 = t2 ^ t6;    
        int    t8 = t2 | t6;    
        int    t9 = d ^ t8;    
        X2 = t5 ^ t9;    
        int    t11 = t1 ^ t9;    
        int    t12 = X0 & t11;    
        X3 = t4 ^ t12;    
        X1 = X3 ^ (X0 ^ t11);
    }

    /**
     * S4 - { 1,15, 8, 3,12, 0,11, 6, 2, 5, 4,10, 9,14, 7,13 } - 15 terms.
     */
    private void sb4(int a, int b, int c, int d)    
    {
        int    t1 = a ^ d;        
        int    t2 = d & t1;    
        int    t3 = c ^ t2;    
        int    t4 = b | t3;    
        X3 = t1 ^ t4;    
        int    t6 = ~b;        
        int    t7 = t1 | t6;    
        X0 = t3 ^ t7;    
        int    t9 = a & X0;        
        int    t10 = t1 ^ t6;    
        int    t11 = t4 & t10;    
        X2 = t9 ^ t11;    
        X1 = (a ^ t3) ^ (t10 & X2);
    }

    /**
     * InvS4 - { 5, 0, 8, 3,10, 9, 7,14, 2,12,11, 6, 4,15,13, 1 } - 15 terms.
     */
    private void ib4(int a, int b, int c, int d)    
    {
        int    t1 = c | d;        
        int    t2 = a & t1;    
        int    t3 = b ^ t2;    
        int    t4 = a & t3;    
        int    t5 = c ^ t4;    
        X1 = d ^ t5;        
        int    t7 = ~a;        
        int    t8 = t5 & X1;    
        X3 = t3 ^ t8;    
        int    t10 = X1 | t7;    
        int    t11 = d ^ t10;    
        X0 = X3 ^ t11;    
        X2 = (t3 & t11) ^ (X1 ^ t7);
    }

    /**
     * S5 - {15, 5, 2,11, 4,10, 9,12, 0, 3,14, 8,13, 6, 7, 1 } - 16 terms.
     */
    private void sb5(int a, int b, int c, int d)    
    {
        int    t1 = ~a;        
        int    t2 = a ^ b;        
        int    t3 = a ^ d;        
        int    t4 = c ^ t1;    
        int    t5 = t2 | t3;    
        X0 = t4 ^ t5;    
        int    t7 = d & X0;        
        int    t8 = t2 ^ X0;    
        X1 = t7 ^ t8;    
        int    t10 = t1 | X0;    
        int    t11 = t2 | t7;    
        int    t12 = t3 ^ t10;    
        X2 = t11 ^ t12;    
        X3 = (b ^ t7) ^ (X1 & t12);
    }

    /**
     * InvS5 - { 8,15, 2, 9, 4, 1,13,14,11, 6, 5, 3, 7,12,10, 0 } - 16 terms.
     */
    private void ib5(int a, int b, int c, int d)    
    {
        int    t1 = ~c;
        int    t2 = b & t1;
        int    t3 = d ^ t2;
        int    t4 = a & t3;
        int    t5 = b ^ t1;
        X3 = t4 ^ t5;
        int    t7 = b | X3;
        int    t8 = a & t7;
        X1 = t3 ^ t8;
        int    t10 = a | d;
        int    t11 = t1 ^ t7;
        X0 = t10 ^ t11;
        X2 = (b & t10) ^ (t4 | (a ^ c));
    }

    /**
     * S6 - { 7, 2,12, 5, 8, 4, 6,11,14, 9, 1,15,13, 3,10, 0 } - 15 terms.
     */
    private void sb6(int a, int b, int c, int d)    
    {
        int    t1 = ~a;        
        int    t2 = a ^ d;        
        int    t3 = b ^ t2;    
        int    t4 = t1 | t2;    
        int    t5 = c ^ t4;    
        X1 = b ^ t5;        
        int    t7 = t2 | X1;    
        int    t8 = d ^ t7;    
        int    t9 = t5 & t8;    
        X2 = t3 ^ t9;    
        int    t11 = t5 ^ t8;    
        X0 = X2 ^ t11;    
        X3 = (~t5) ^ (t3 & t11);
    }

    /**
     * InvS6 - {15,10, 1,13, 5, 3, 6, 0, 4, 9,14, 7, 2,12, 8,11 } - 15 terms.
     */
    private void ib6(int a, int b, int c, int d)    
    {
        int    t1 = ~a;        
        int    t2 = a ^ b;        
        int    t3 = c ^ t2;    
        int    t4 = c | t1;    
        int    t5 = d ^ t4;    
        X1 = t3 ^ t5;    
        int    t7 = t3 & t5;    
        int    t8 = t2 ^ t7;    
        int    t9 = b | t8;    
        X3 = t5 ^ t9;    
        int    t11 = b | X3;    
        X0 = t8 ^ t11;    
        X2 = (d & t1) ^ (t3 ^ t11);
    }

    /**
     * S7 - { 1,13,15, 0,14, 8, 2,11, 7, 4,12,10, 9, 3, 5, 6 } - 16 terms.
     */
    private void sb7(int a, int b, int c, int d)    
    {
        int    t1 = b ^ c;        
        int    t2 = c & t1;    
        int    t3 = d ^ t2;    
        int    t4 = a ^ t3;    
        int    t5 = d | t1;    
        int    t6 = t4 & t5;    
        X1 = b ^ t6;        
        int    t8 = t3 | X1;    
        int    t9 = a & t4;    
        X3 = t1 ^ t9;    
        int    t11 = t4 ^ t8;    
        int    t12 = X3 & t11;    
        X2 = t3 ^ t12;    
        X0 = (~t11) ^ (X3 & X2);
    }

    /**
     * InvS7 - { 3, 0, 6,13, 9,14,15, 8, 5,12,11, 7,10, 1, 4, 2 } - 17 terms.
     */
    private void ib7(int a, int b, int c, int d)    
    {
        int t3 = c | (a & b);
        int    t4 = d & (a | b);
        X3 = t3 ^ t4;
        int    t6 = ~d;
        int    t7 = b ^ t4;
        int    t9 = t7 | (X3 ^ t6);
        X1 = a ^ t9;
        X0 = (c ^ t7) ^ (d | X1);
        X2 = (t3 ^ X1) ^ (X0 ^ (a & X3));
    }

    /**
     * Apply the linear transformation to the register set.
     */
    private void LT()
    {
        int x0  = rotateLeft(X0, 13);
        int x2  = rotateLeft(X2, 3);
        int x1  = X1 ^ x0 ^ x2 ;
        int x3  = X3 ^ x2 ^ x0 << 3;

        X1  = rotateLeft(x1, 1);
        X3  = rotateLeft(x3, 7);
        X0  = rotateLeft(x0 ^ X1 ^ X3, 5);
        X2  = rotateLeft(x2 ^ X3 ^ (X1 << 7), 22);
    }

    /**
     * Apply the inverse of the linear transformation to the register set.
     */
    private void inverseLT()
    {
        int x2 = rotateRight(X2, 22) ^ X3 ^ (X1 << 7);
        int x0 = rotateRight(X0, 5) ^ X1 ^ X3;
        int x3 = rotateRight(X3, 7);
        int x1 = rotateRight(X1, 1);
        X3 = x3 ^ x2 ^ x0 << 3;
        X1 = x1 ^ x0 ^ x2;
        X2 = rotateRight(x2, 3);
        X0 = rotateRight(x0, 13);
    }
}
