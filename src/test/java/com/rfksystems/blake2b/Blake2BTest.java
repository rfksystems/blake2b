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
import java.util.Arrays;

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

    @Test
    public void it_writes_all_digest_bytes_without_touching_output_padding() throws Exception {
        final int[] sizes = {1, 7, 8, 9, 24, 63, 64};
        // Reference digests from Python hashlib.blake2b(bytes(i % 256 for i in range(257)), digest_size=size).
        final String[] expected = {
                "ca",
                "7da1d0fbe146a7",
                "2210e66ecf77af81",
                "17310706188f92f83f",
                "4e8e430a4089ea0658947febd954fca8f03beeeec4175054",
                "182ea1e275535b81cb7db130b4d5eb1ef7e0f889af0723cbd9ed5374e63c1513111a603e3db1815d71a176924b615de97d060ea282ee3968f93166d2a542bc",
                "d8bfe068de0b4f9fa876a3f8024eb9f7b0029fd5dcf251199e065cee89e1a282c8dbf0442f2ade7294ac1c6be19b388dc990c34d8cb79f5f10c54fa813834fda"
        };
        final byte[] input = new byte[257];
        for (int i = 0; i < input.length; i++) {
            input[i] = (byte) i;
        }
        for (int i = 0; i < sizes.length; i++) {
            final Blake2b digest = new Blake2b(null, sizes[i], null, null);
            final byte[] output = new byte[sizes[i] + 6];
            Arrays.fill(output, (byte) 0x5a);
            digest.update(input, 0, input.length);
            assertThat(digest.digest(output, 3)).isEqualTo(sizes[i]);
            assertThat(Arrays.copyOfRange(output, 3, 3 + sizes[i])).isEqualTo(decodeHexString(expected[i]));
            assertThat(Arrays.copyOfRange(output, 0, 3)).isEqualTo(new byte[]{0x5a, 0x5a, 0x5a});
            assertThat(Arrays.copyOfRange(output, 3 + sizes[i], output.length)).isEqualTo(new byte[]{0x5a, 0x5a, 0x5a});
        }
    }

    @Test
    public void it_reuses_and_copies_keyed_digests_across_block_boundaries() throws Exception {
        final byte[] key = new byte[64];
        final byte[] salt = new byte[16];
        final byte[] personalization = new byte[16];
        final byte[] input = new byte[257];
        for (int i = 0; i < key.length; i++) {
            key[i] = (byte) i;
        }
        for (int i = 0; i < salt.length; i++) {
            salt[i] = (byte) i;
            personalization[i] = (byte) (i + 16);
        }
        for (int i = 0; i < input.length; i++) {
            input[i] = (byte) i;
        }
        // Reference: hashlib.blake2b(input, digest_size=24, key=key, salt=salt, person=personalization).
        final byte[] expected = decodeHexString("bd7a7fff496dbd318b615c34183a2c945dfc525317853f43");
        final Blake2b digest = new Blake2b(key, 24, salt, personalization);
        digest.update(input, 0, 129);
        final Blake2b copy = new Blake2b(digest);
        digest.update(input, 129, input.length - 129);
        copy.update(input, 129, input.length - 129);
        final byte[] output = new byte[24];
        digest.digest(output, 0);
        assertThat(output).isEqualTo(expected);
        copy.digest(output, 0);
        assertThat(output).isEqualTo(expected);
        for (byte value : input) {
            digest.update(value);
        }
        digest.digest(output, 0);
        assertThat(output).isEqualTo(expected);
        digest.update(input, 0, 128);
        digest.reset();
        digest.update(input, 0, input.length);
        digest.digest(output, 0);
        assertThat(output).isEqualTo(expected);
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
