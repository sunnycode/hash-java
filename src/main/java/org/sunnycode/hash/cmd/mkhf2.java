package org.sunnycode.hash.cmd;

/**
 * Licensed to the Apache Software Foundation (ASF) under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The ASF licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the License. You may obtain a
 * copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */


import java.io.File;
import java.nio.ByteBuffer;
import java.nio.LongBuffer;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.Scanner;
import java.util.Set;
import java.util.logging.Logger;

import org.sunnycode.hash.LongHash;
import org.sunnycode.hash.file2.ByteSize;
import org.sunnycode.hash.file2.HashFile2Builder;
import org.sunnycode.hash.impl.MurmurHash;

public class mkhf2 {
  private static final Logger log = Logger.getLogger(mkhf2.class.getName());

  public static void main(String[] args) throws Exception {
    LinkedList<String> theArgs = new LinkedList<String>();
    theArgs.addAll(Arrays.asList(args));

    String outFile = theArgs.removeFirst();
    long expectedElements = Long.parseLong(theArgs.removeFirst());

    String delim = System.getProperty("delim", "\t");

    ByteSize keySize = ByteSize.valueOf(System.getProperty("keySize", "ZERO"));
    ByteSize valueSize = ByteSize.valueOf(System.getProperty("valueSize", "EIGHT"));

    boolean isAssociative = Boolean.valueOf(System.getProperty("isAssociative", "true"));
    boolean isLongHash = Boolean.valueOf(System.getProperty("isLongHash", "true"));
    boolean isLargeCapacity = Boolean.valueOf(System.getProperty("isLargeCapacity", "true"));
    boolean isLargeFile = Boolean.valueOf(System.getProperty("isLargeFile", "true"));

    LongHash murmur2 = new MurmurHash();

    HashFile2Builder hf =
        new HashFile2Builder(isAssociative, outFile, expectedElements, keySize, valueSize,
            isLongHash, isLargeCapacity, isLargeFile, true, true);

    log.info("adding...");

    final ByteBuffer klconvert = ByteBuffer.allocate(8);
    final LongBuffer klongbuf = klconvert.asLongBuffer();
    final ByteBuffer vlconvert = ByteBuffer.allocate(8);
    final LongBuffer vlongbuf = vlconvert.asLongBuffer();

    final Set<Long> already = new HashSet<Long>();

    long j = 0;
    for (String file : theArgs) {
      long i = 0;
      try (Scanner x = new Scanner(new File(file))) {
        while (x.hasNextLine()) {
          String n = x.nextLine();
          i += 1;

          String[] v = n.split(delim);

          if (v.length == 3) {
            long valueLong = Long.parseLong(v[1]);
            setLongBytes(vlconvert, vlongbuf, valueLong);
            byte[] value = vlconvert.array();

            Long hashVal = murmur2.getLongHashCode(v[2].getBytes("UTF-8"));
            setLongBytes(klconvert, klongbuf, hashVal);
            byte[] key = klconvert.array();

            if (!already.contains(hashVal)) {
              hf.add(key, value);
              already.add(hashVal);
            } else {
              log.fine("ALREADY line : " + n);
            }
          } else {
            log.fine("BAD line : " + n);
          }

          if (i % 100000 == 0) {
            log.info(file + " : " + i + " " + j + " " + n);
          }

          j += 1;
        }
      }
    }

    log.info(j + " building...");
    hf.finish();
    log.info(j + " done.");
  }

  private static void setLongBytes(final ByteBuffer convert, final LongBuffer longbuf, long value) {
    longbuf.rewind();
    longbuf.put(value);
  }
}
