import tlsdial from 'k6/x/tlsdial';
import { check } from 'k6';
import { Counter } from 'k6/metrics';

export const epDataSent = new Counter('tls_data_sent');
export const epDataRecv = new Counter('tls_data_received');

const conf = {
    insecure_skip_verify: true,
    ca_certificates: [
        `-----BEGIN CERTIFICATE-----
        MIID1zCCAr+gAwIBAgIGQTAwMDAzMA0GCSqGSIb3DQEBCwUAMIGYMQswCQYDVQQG
        EwJVUzELMAkGA1UECBMCVFgxETAPBgNVBAcTCEJ1bHZlcmRlMRAwDgYDVQQKEwdG
        dXR1cmV4MRAwDgYDVQQLEwdTdXBwb3J0MSEwHwYDVQQDExhGdXR1cmV4IFRlc3Qg
        Um9vdCBTU0wgQ0ExIjAgBgkqhkiG9w0BCQEWE3N1cHBvcnRAZnV0dXJleC5jb20w
        IBcNMTIwODA3MDAwMDAwWhgPMjEwMDA4MDcwMDAwMDBaMIGYMQswCQYDVQQGEwJV
        UzELMAkGA1UECBMCVFgxETAPBgNVBAcTCEJ1bHZlcmRlMRAwDgYDVQQKEwdGdXR1
        cmV4MRAwDgYDVQQLEwdTdXBwb3J0MSEwHwYDVQQDExhGdXR1cmV4IFRlc3QgUm9v
        dCBTU0wgQ0ExIjAgBgkqhkiG9w0BCQEWE3N1cHBvcnRAZnV0dXJleC5jb20wggEi
        MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDQR13FN4dVO/6fTd346pDEVr8A
        +zvNHzSWaiS0kZsWLgApLd9UTdlbdG1oCEyzNii5uG8YMZ8GCtiaDO2xPqsdW7nv
        hGW3cehCHwjHg25Rp8UeBvSAOwIUIgcwYi8tK5+JM7SABMubWqM1R7JJSAkH4sVv
        8Lb8ADM1QEOLuh/gm4PSI9424dB+ViO6ICfroheLz+CqdNeXKQnVIlDc9Ez0sMHS
        +FYmjpdY2vFErwuh4FcJiUogALjZHnGYWnQPgjBsdOpK0t1m91wNFFNIw7Z/RXzH
        rCksAsFiSVPyuUCuXIREH48TO7NiVqUvuC9sPGu1nXGV3KQ7Z1F1qv36jyvRAgMB
        AAGjIzAhMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgIEMA0GCSqGSIb3
        DQEBCwUAA4IBAQCETPz+Wqwg7EVUmgMvEtxZJj3iR11+o3AraPQWm1d31HG7MfOt
        1RM/TOFKJFRIt+hnazD5M7c+RA+5rVzRgwT2w1y1t/ZitxKoWH633dyCAHjiKT5k
        BKmpNwBqb+yENy7rE2GMhXU8sDLj3d2cLTgTIV+RXw/fcgE9Vm9eJbpzli4JBlfg
        MhRx2N5rNp4X88sT8JAvUUWuyzA5/6Ep6UHjMXXpKOYlo1DlSCTJxrYbN/GdgqzR
        QN2qt69gyOPLiLBYTyK/328L80DzMHIDLvC4dNRTIPbRYRVXEexZvl0uiOW8qqgC
        j4DMb4BcRsDcN1srXDGjRpPnMYpioIxJ+JzL
        -----END CERTIFICATE----- `,
        `-----BEGIN CERTIFICATE-----
        MIIEGzCCAwOgAwIBAgIHRfZ+AAACIjANBgkqhkiG9w0BAQsFADCBmDELMAkGA1UE
        BhMCVVMxCzAJBgNVBAgTAlRYMREwDwYDVQQHEwhCdWx2ZXJkZTEQMA4GA1UEChMH
        RnV0dXJleDEQMA4GA1UECxMHU3VwcG9ydDEhMB8GA1UEAxMYRnV0dXJleCBUZXN0
        IFJvb3QgU1NMIENBMSIwIAYJKoZIhvcNAQkBFhNzdXBwb3J0QGZ1dHVyZXguY29t
        MCAXDTE0MDUxMjAwMDAwMFoYDzIxMDAwNTEyMDAwMDAwWjCBnjELMAkGA1UEBhMC
        VVMxCzAJBgNVBAgTAlRYMREwDwYDVQQHEwhCdWx2ZXJkZTEQMA4GA1UEChMHRnV0
        dXJleDEQMA4GA1UECxMHU3VwcG9ydDEnMCUGA1UEAxMeRnV0dXJleCBUZXN0IFBy
        b2R1Y3Rpb24gU1NMIENBMSIwIAYJKoZIhvcNAQkBFhNzdXBwb3J0QGZ1dHVyZXgu
        Y29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA+Hl8/YfnS8jj2c1e
        oXt7UUQS3PMjkFRyli6qzVkvNhhs+NOCWnCBgTh9x/mQHH0GOb7xV947wn6/dBjv
        2k/KIulkV1S9O4Snsy2S5pp9uZLfKNIvO96UII1nUpcLXPB60KWoTUuGkTMTMBCU
        7/zeEJvC7UcaHKjX/5XZHaEilI5HMfym57Ht0uXulOvBqLb30gebN2AbsjjXDY8U
        Q3LDblOWBaLo1+fg51lXoXvz0Tw400KBv51FU82FAOG8DUSeIo8opZsfPX0x7/1y
        ffuI8hkYVYg9LF+xE+yhr7HluZnubE0z8s/FZAxuH+agd1g9xb9tRGefldYictbC
        4own3QIDAQABo2AwXjAfBgNVHSMEGDAWgBToFd4IoztrADgTo8KEuwSqBhPrqzAd
        BgNVHQ4EFgQUumijxTif1gA3g6uI0iGgUjNoFE4wDwYDVR0TAQH/BAUwAwEB/zAL
        BgNVHQ8EBAMCAQYwDQYJKoZIhvcNAQELBQADggEBAMYmoxanHlwxSdyK3XQF5Pa9
        cBA8pPDO9WW9PofqmaBxkVAlIx6vPHeLJ03tmt05tkEI3eSvK1r4S+wyKceZDuQk
        vmITCdERqlgpkrck3tRFgFCbTLBoAGrIQzmQh7gaaIldJY7uxDzjdoTE8hk/0dLp
        d5MbGJn7dUdC4JLuCZd0W9jopqZzgKd/DmTXv6CE5GrS0aDZJJuWkWSYllaDP47Z
        sk5CASCVc/8oyQzHG3Ht5RTidi5SOoCPQs+UWV+QQfMC43KfGj820l8XEN6h/VnK
        VZ9evzuDX6Ptbmtas4I9JdC6WgCKEYZvawe75lpxAI8mnHfDl88QfqQD2XRVP+o=
        -----END CERTIFICATE-----`,
        `-----BEGIN CERTIFICATE-----
        MIIEKjCCAxKgAwIBAgIHBQDEAAAAbDANBgkqhkiG9w0BAQsFADCBnjELMAkGA1UE
        BhMCVVMxCzAJBgNVBAgTAlRYMREwDwYDVQQHEwhCdWx2ZXJkZTEQMA4GA1UEChMH
        RnV0dXJleDEQMA4GA1UECxMHU3VwcG9ydDEnMCUGA1UEAxMeRnV0dXJleCBUZXN0
        IFByb2R1Y3Rpb24gU1NMIENBMSIwIAYJKoZIhvcNAQkBFhNzdXBwb3J0QGZ1dHVy
        ZXguY29tMCAXDTE0MDUxMjAwMDAwMFoYDzIxMDAwNTEyMDAwMDAwWjCBpzELMAkG
        A1UEBhMCVVMxCzAJBgNVBAgMAlRYMREwDwYDVQQHDAhCdWx2ZXJkZTEQMA4GA1UE
        CgwHRnV0dXJleDEQMA4GA1UECwwHU3VwcG9ydDEwMC4GA1UEAwwnRnV0dXJleCBU
        ZXN0IEN1c3RvbWVyIFByb2R1Y3Rpb24gU1NMIENBMSIwIAYJKoZIhvcNAQkBFhNz
        dXBwb3J0QGZ1dHVyZXguY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
        AQEAx0RpVCJugeJieBfVt4kWwBYaPWr1QfRkO2kzjJQthhISPQjJwWgzZUCLOgkG
        WEU9D/+6hhrghrTtpJLSzxk1Ht5scjPVAl9mXiOfa4GaKccXzxh9MXeFRRda87wh
        ZDv1xyCYpa58qBL47ES82xDfZAUpUzGvsSN0yh3Ng3PjT4wl+GCc3yBQVbnWRHpE
        ysHJ0qFyzRfhAtbsGVOMnh7x2QCdqMUd+MbZOv53ficJT+ATtqgo4zFgYqurNBA7
        3A03lC/xbvl9vXwjiHkVrs4VSWmKzj+su2c5Efz4vdO7eAXjZVLvJbXYBJ6glosQ
        EQyM7qTufXxIw78B1jYL6TZifwIDAQABo2AwXjAfBgNVHSMEGDAWgBS6aKPFOJ/W
        ADeDq4jSIaBSM2gUTjAdBgNVHQ4EFgQUXfnQ3n+LM82CaB7JQLr1POJVoWIwDwYD
        VR0TAQH/BAUwAwEB/zALBgNVHQ8EBAMCAQYwDQYJKoZIhvcNAQELBQADggEBAEhd
        yE9GcB9Pdxfc1125n1JpWGlmcB0cbv4dMLT6jMGnsI8QPaoYT8VZpqRQd4Y4E/md
        kD3E55MUq7SGihb8JAEy7STKo2iNv3v5zNTZTl8MW0AL0++q1g5dFM9jwAFebLtJ
        aNBgoeBaVWshWraImFJ33WeitqrW8TmTsnY0CZhxGGtl+WAgNavqXVTMSCIJdZFv
        CWURDSXMogdaz437sgOIaOJSCcA3tsGVFxYrJMSlAG/8UIFUvePuEZ4iiVqyKFiY
        VKuG0Cku6dW+DuzhyZqiQHYt2aOcdfQIPu6AfeD9jcH/1xuIkbL85US1hI8+TsNP
        6alqxTBOyXv9nPpLa/U=
        -----END CERTIFICATE-----`
    ],
    client_certificate: `-----BEGIN CERTIFICATE-----
        MIIDzTCCArWgAwIBAgIHRfZaAACTNDANBgkqhkiG9w0BAQsFADCBpzELMAkGA1UE
        BhMCVVMxCzAJBgNVBAgMAlRYMREwDwYDVQQHDAhCdWx2ZXJkZTEQMA4GA1UECgwH
        RnV0dXJleDEQMA4GA1UECwwHU3VwcG9ydDEwMC4GA1UEAwwnRnV0dXJleCBUZXN0
        IEN1c3RvbWVyIFByb2R1Y3Rpb24gU1NMIENBMSIwIAYJKoZIhvcNAQkBFhNzdXBw
        b3J0QGZ1dHVyZXguY29tMB4XDTE4MDkxOTAwMDAwMFoXDTMwMDkxOTAwMDAwMFow
        gaUxCzAJBgNVBAYTAlVTMQ4wDAYDVQQIDAVUZXhhczERMA8GA1UEBwwIQnVsdmVy
        ZGUxEDAOBgNVBAoMB0Z1dHVyZXgxCzAJBgNVBAsMAlFBMRMwEQYDVQQMDApRQSBN
        YW5hZ2VyMRwwGgYDVQQDDBNQYXVsIE1vb3JlIFJTQSBQcm9kMSEwHwYJKoZIhvcN
        AQkBFhJwbW9vcmVAZnV0dXJleC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
        ggEKAoIBAQDnylW8ArTCyUvWN4RkwpgFRYmWI+vtODwruYCUHLpItFOGpt7T/oMS
        9D5yARstKbOYIItPzjiRbmqw1X9YHEFKh9t/x85g1LUWGbdhjj0TD0M6X8oY1fU5
        W7Ai3N0nH2esOkECKj2prj8SWJDHUGUcB/MGUrV4n6TuVO7xoi+giyhOoUVvkHUT
        CXrWQiQwDy7V9eUm0Grt5w2x+2yE7INsjNx84QeiM1+3ESplwJ5AWxlV2toZR2wc
        IoVhSjI6iACyN0f82pVIkbemKDvyOGZweL60hL3Y4rvSM+2vLriwUopVdWQNjU4f
        5Ypuv5jBIaiM/AnDE0zcZFDZkzNlhwHhAgMBAAEwDQYJKoZIhvcNAQELBQADggEB
        AMOPbaYX+fxwfSp9lIGaakzPQYiP+xcC0DkbtCbE/MEXVlmEw1mVXuS5ZFpN5g+L
        apkD6MVICvRcCnCey80AqLvU8c/fkOKoioQnNNIroJb7B1NpZQyl6d+p8KElzNH+
        4su1ke094oBNFPuaz2e9j75pSBeYr6lz9HWyWmvWITHK6XhFEPoRbOWY+lceqe1x
        jsb5mkZdSxacBVEZwmB6WfFm7ZR7cVeQlsVFIWbWiQyQYGHlHDcD2HsJfqciGuwj
        qrkR9knLxAqXcab9mW5wDJpHuEaZzV7lG3ZBOqsvNoqimj4dB0uDjB8osSRvHdiL
        QYfedX0EwJ3wWUJN9e6rTfw=
        -----END CERTIFICATE-----`,
    client_key: `-----BEGIN RSA PRIVATE KEY-----
        MIIEpAIBAAKCAQEA58pVvAK0wslL1jeEZMKYBUWJliPr7Tg8K7mAlBy6SLRThqbe
        0/6DEvQ+cgEbLSmzmCCLT844kW5qsNV/WBxBSofbf8fOYNS1Fhm3YY49Ew9DOl/K
        GNX1OVuwItzdJx9nrDpBAio9qa4/EliQx1BlHAfzBlK1eJ+k7lTu8aIvoIsoTqFF
        b5B1Ewl61kIkMA8u1fXlJtBq7ecNsftshOyDbIzcfOEHojNftxEqZcCeQFsZVdra
        GUdsHCKFYUoyOogAsjdH/NqVSJG3pig78jhmcHi+tIS92OK70jPtry64sFKKVXVk
        DY1OH+WKbr+YwSGojPwJwxNM3GRQ2ZMzZYcB4QIDAQABAoIBAAHvQ2XtU9roWTSx
        g+5fXWt12B8jr51sQbxPsQ4La1aeArB2BhgY4LkwxrCm57YpyfD0HJWO8BPuqv9M
        2OJAYh8gISng3g0a2WQU1N4AlOvqzbHYCNTKPGC9LiwsUcA41+GtHsvI1HjtFmOt
        z4+KUT25p0KfQBqAopzGorPrmaAqZRu9WyFUaE0MM4wRRvuEWMa9tPYwjgXizj77
        e5uNdQQrv2ZPgmK9rkzFbvHg6NzJmOM9JeGZt41PkmlyiYOVwEaRIbhHkw8zjvUC
        7XCY7o2fHhUKLo4o98pg9m+UF91yu5b+M0U81BwAWR6hn0UaiJv2Y3sJkv+DVHHR
        1DsUX70CgYEA9Ea5MAa9Zcds54YRCoQdkR2Bn4FVxEsh+kup8aEqcQHramTPfv3G
        dlJY7hXnxWLQMOSF+F7j8UDv2+A4G6H9iGWRUjveS82cc8zPcMO3pe3w0mu+chuQ
        EYZKoSXh/HpF+kLmK41q/Mqc5Du4AG8+qjKUiLtCH4rZ3D6tBMgfvvsCgYEA8uo0
        bgKMGHFI/eSh3dzuM+jmmt9FMtTtQzxTE3GItXUJi1bS9oHDAYSrQ6duuw4AD9UA
        HcAxVO9Do+EJNtTKLyQ1gQcMgjbO0HPX4WZ9Z8wphi9g7YKTvcpjiR/AIBx/NPB+
        P8ig/DxD6Zocs5e2MwF745SpYTn8q0q96Oyue9MCgYEA1BCd7pq7TCOwYOLb4nRF
        stiZ0p6Wlb3gNon/dFzFGqxe8tOn64hnBguBVtg/iPW65edOgwvl+Wi1kv3518tu
        7j22xlxhJQ/QNhvlLvFKesuxmQuenzNchEpAedwIb4a7P4NajQ7Nhb5kLCPIHuB0
        147nsjhXNEj3z6O90vvly4cCgYBa/OcOnd2j+isBDvaih/KhdweJ0z+0PpVwrdPg
        YJJ4hZJBow/6TbihhPQxrzGG10Omqn4UprzTt5t6cvxkkWf6KHHyFpXU4HqvEfU2
        9JDcpFiZbn27+UElwf1ui3oHjSUIy1w+wAOs91Xo1lUR4C3bBR9Gq5SWWoYOEzz3
        VlA1CQKBgQDFBINJczV0autd3itk5bZiMzre8qejA+oIzy5Iy7FD41XElqETC6/Q
        t8scaOr6dGbNCrTivzc3EsqzC9M1iyWfALQGP0fdzLVHCVoC6IcvTH1F2U2S9jA5
        U/wRcC6R1FPRPtXHqvarZb1mwAkwOGTgKI4yfQtGEgdWfF7iwgCZKA==
        -----END RSA PRIVATE KEY-----`
}

const conn = tlsdial.dial('sibs02:2001', conf);

export default function () {
    let message = '[AOECHO;AGtest from k6;]'
    tlsdial.writeLn(conn, message);
    epDataSent.add(message.length);
    let recv = tlsdial.readstring(conn);
    epDataRecv.add(recv.length);
    check(recv, {
        'verify ag tag': (recv) => recv.includes('AGtest from k6')
    });
}