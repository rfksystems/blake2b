package com.rfksystems.blake2b;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.rfksystems.blake2b.security.*;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.junit.Test;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Type;
import java.security.MessageDigest;
import java.security.Security;
import java.util.Collection;

import static com.google.common.truth.Truth.assertThat;

public class Blake2BTest {
    private final Gson gson = new Gson();

    public Blake2BTest() {
        Security.addProvider(new Blake2bProvider());
    }

    private static byte[] decodeHexString(final String value) throws DecoderException {
        return Hex.decodeHex(value.toCharArray());
    }

    @Test
    public void it_digests_keyed_entries() throws Exception {
        final Collection<DataSourceEntry> keyedEntries = keyedDataSource();

        for (final DataSourceEntry entry : keyedEntries) {
            final byte[] key = entry.keyBytes();
            final byte[] in = entry.inBytes();

            final Blake2b digest = new Blake2b(key);

            digest.update(in, 0, in.length);

            final byte[] out = new byte[64];
            digest.digest(out, 0);

            assertThat(out).isEqualTo(entry.hashBytes());
        }
    }

    @Test
    public void it_digests_non_keyed_entries() throws Exception {
        final Collection<DataSourceEntry> nonKeyedEntries = nonKeyedDataSource();

        for (final DataSourceEntry entry : nonKeyedEntries) {
            final byte[] in = entry.stringInBytes();

            final Blake2b digest = new Blake2b();

            digest.update(in, 0, in.length);

            final byte[] out = new byte[64];
            digest.digest(out, 0);

            assertThat(out).isEqualTo(entry.hashBytes());
        }
    }

    @Test
    public void it_provides_valid_blake2b_160() throws Exception {
        final MessageDigest digest = MessageDigest.getInstance(Blake2b.BLAKE2_B_160);

        assertThat(digest).isInstanceOf(Blake2b160Digest.class);

        digest.update("hello".getBytes());

        assertThat(digest.digest()).isEqualTo(decodeHexString("b5531c7037f06c9f2947132a6a77202c308e8939"));
    }

    @Test
    public void it_provides_valid_blake2b_256() throws Exception {
        final MessageDigest digest = MessageDigest.getInstance(Blake2b.BLAKE2_B_256);

        assertThat(digest).isInstanceOf(Blake2b256Digest.class);

        digest.update("hello".getBytes());

        assertThat(digest.digest()).isEqualTo(decodeHexString(
                "324dcf027dd4a30a932c441f365a25e86b173defa4b8e58948253471b81b72cf"
        ));

    }

    @Test
    public void it_provides_valid_blake2b_384() throws Exception {
        final MessageDigest digest = MessageDigest.getInstance(Blake2b.BLAKE2_B_384);

        assertThat(digest).isInstanceOf(Blake2b384Digest.class);

        digest.update("hello".getBytes());

        assertThat(digest.digest()).isEqualTo(decodeHexString(
                "85f19170be541e7774da197c12ce959b91a280b2f23e3113d6638a3335507ed72ddc30f81244dbe9fa8d195c23bceb7e"
        ));
    }

    @Test
    public void it_provides_valid_blake2b_512() throws Exception {
        final MessageDigest digest = MessageDigest.getInstance(Blake2b.BLAKE2_B_512);

        assertThat(digest).isInstanceOf(Blake2b512Digest.class);

        digest.update("hello".getBytes());


        assertThat(digest.digest()).isEqualTo(decodeHexString(
                "e4cfa39a3d37be31c59609e807970799caa68a19bfaa15135f165085e01d41a65ba1e1b146aeb6bd0092b49eac214c103ccfa3a365954bbbe52f74a2b3620c94"
        ));
    }

    /**
     * From https://fossies.org/linux/john/src/rawBLAKE2_512_fmt_plug.c
     */
    private Collection<DataSourceEntry> nonKeyedDataSource() {
        return getDataSourceEntries("/non_keyed_source.json");
    }

    /**
     * From https://blake2.net/blake2b-test.txt
     */
    private Collection<DataSourceEntry> keyedDataSource() {
        return getDataSourceEntries("/keyed_source.json");
    }

    private Collection<DataSourceEntry> getDataSourceEntries(final String resource) {
        final Type type = new TypeToken<Collection<DataSourceEntry>>() {
        }.getType();
        final InputStream in = Blake2BTest.class.getResourceAsStream(resource);
        return gson.fromJson(new InputStreamReader(in), type);
    }

    private static class DataSourceEntry {
        String key;
        String hash;
        String in;
        String stringIn;

        byte[] keyBytes() throws DecoderException {
            return decodeHexString(key);
        }

        byte[] hashBytes() throws DecoderException {
            return decodeHexString(hash);
        }

        byte[] inBytes() throws DecoderException {
            return decodeHexString(in);
        }

        byte[] stringInBytes() throws DecoderException {
            return stringIn.getBytes();
        }
    }
}
