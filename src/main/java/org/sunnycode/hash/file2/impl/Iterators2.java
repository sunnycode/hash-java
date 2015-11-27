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
package org.sunnycode.hash.file2.impl;

import static org.sunnycode.hash.file2.impl.FileOperations2.read;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Iterator;
import java.util.concurrent.atomic.AtomicLong;

import org.sunnycode.hash.file2.ByteSize;
import org.sunnycode.hash.file2.HashEntry;

/**
 * Implementation of iterators used by HashFile.
 */
public class Iterators2 {
  public static Iterable<byte[]> getEmptyIterable() {
    return new Iterable<byte[]>() {
      @Override
      public Iterator<byte[]> iterator() {
        return new Iterator<byte[]>() {
          @Override
          public boolean hasNext() {
            return false;
          }

          @Override
          public byte[] next() {
            return null;
          }

          @Override
          public void remove() {
            throw new UnsupportedOperationException("remove() not supported");
          }
        };
      }
    };
  }

  public static Iterable<HashEntry> getSequentialIterable(final String hashFilePath) {
    return new Iterable<HashEntry>() {
      @Override
      public Iterator<HashEntry> iterator() {
        final Header2 header;
        final FileOperations2 fileOps;
        final long eod;

        try (RandomAccessFile in = new RandomAccessFile(hashFilePath, "r")) {
          header = Header2.readHeader(in);
          fileOps = FileOperations2.fromHeader(header);
          eod = fileOps.getEndOfData(in);
        } catch (Exception e) {
          throw new RuntimeException("Unable to read hashfile header: " + e.getMessage(), e);
        }

        final long elementCount = header.getElementCount();
        final long startPos = header.getTotalHeaderLength();

        final DataInputStream input;

        try {
          input =
              new DataInputStream(new BufferedInputStream(new FileInputStream(hashFilePath),
                  FileOperations2.ITERATOR_READ_BUFFER_LENGTH));

          input.skipBytes((int) startPos);
        } catch (IOException e) {
          throw new RuntimeException("Unable to read hashfile header: " + e.getMessage(), e);
        }

        return new Iterator<HashEntry>() {
          AtomicLong pos = new AtomicLong(startPos);
          AtomicLong remaining = new AtomicLong(elementCount);

          protected void finalize() {
            try {
              input.close();
            } catch (Exception ignored) {}
          }

          @Override
          public synchronized boolean hasNext() {
            return pos.get() < eod && remaining.get() > 0;
          }

          @Override
          public void remove() {
            throw new UnsupportedOperationException("HashFile does not support remove()");
          }

          @Override
          public synchronized HashEntry next() {
            if (!hasNext()) {
              throw new IllegalStateException("next() called past end of iterator");
            }

            remaining.decrementAndGet();
            return fileOps.readHashEntry(input, pos);
          }
        };
      }
    };
  }

  public static Iterable<byte[]> getMultiIterable(final int alignment,
      final RandomAccessFile hashFile, final ByteBuffer hashTableOffsets, int bucketPower,
      final int slotSize, final ByteSize keySize, final ByteSize valueSize,
      final boolean isAssociative, final boolean isLongHash, final boolean isLargeCapacity,
      final boolean isLargeFile, final boolean isUuid, final boolean isPrimitive, final byte[] key) {
    final long currentHashCode = Calculations2.computeHash(key, isLongHash, isUuid);

    int innerSlot = Calculations2.getBucket(currentHashCode, bucketPower);
    int innerSlotBase = innerSlot * slotSize;

    final long innerSlotBasePosition =
        (isLargeCapacity ? hashTableOffsets.getLong(innerSlotBase) : hashTableOffsets
            .getInt(innerSlotBase)) << alignment;

    int slotEntrySize = isLargeCapacity ? 8 : 4;

    final long innerSlotTableSize =
        isLargeCapacity
            ? hashTableOffsets.getLong(innerSlotBase + slotEntrySize)
            : hashTableOffsets.getInt(innerSlotBase + slotEntrySize);

    if (innerSlotTableSize == 0) {
      return Iterators2.getEmptyIterable();
    }

    final int initialSlotIndexToProbe = (int) (Math.abs(currentHashCode) % innerSlotTableSize);

    final ByteBuffer innerSlotTableBytes =
        ByteBuffer.allocate(Calculations2.getHashTableEntrySize(isLongHash, isLargeFile)
            * ((int) innerSlotTableSize));

    final ByteBuffer fileBytes = ByteBuffer.allocate(FileOperations2.RANDOM_READ_BUFFER_LENGTH);

    final int hashEntrySize = Calculations2.getHashTableEntrySize(isLongHash, isLargeFile);

    return new Iterable<byte[]>() {
      @Override
      public Iterator<byte[]> iterator() {
        return new Iterator<byte[]>() {
          int innerSlotIndexToProbe = initialSlotIndexToProbe;
          boolean wrapped = false;
          boolean first = true;
          final int hashSizeBytes = isLongHash ? 8 : 4;
          byte[] next = advance();

          private void readFully() throws IOException {
            synchronized (hashFile) {
              hashFile.seek(innerSlotBasePosition);
              hashFile.readFully(innerSlotTableBytes.array());
            }
          }

          private byte[] advance() {
            try {
              if (first) {
                readFully();
                first = false;
              }

              long searchTrials = 0;

              while (searchTrials < innerSlotTableSize) {
                if (wrapped && innerSlotIndexToProbe >= initialSlotIndexToProbe) {
                  return null;
                }

                int probeLocation = innerSlotIndexToProbe * hashEntrySize;

                long hashCodeAlreadyAtProbeLocation =
                    isLongHash ? innerSlotTableBytes.getLong(probeLocation) : innerSlotTableBytes
                        .getInt(probeLocation);

                long entryPositionAlreadyAtProbeLocation =
                    (isLargeFile
                        ? innerSlotTableBytes.getLong(probeLocation + hashSizeBytes)
                        : innerSlotTableBytes.getInt(probeLocation + hashSizeBytes)) << alignment;

                // if we find an empty location, we can break early because
                // the hash code should have been in the earliest spot
                if (entryPositionAlreadyAtProbeLocation == 0) {
                  return null;
                }

                searchTrials += 1;
                innerSlotIndexToProbe += 1;

                // wrap around if the index passes the table size
                if (innerSlotIndexToProbe >= innerSlotTableSize) {
                  if (!wrapped) {
                    innerSlotIndexToProbe = 0;
                    wrapped = true;
                  } else {
                    return null;
                  }
                }

                // not our hash code - keep trying
                if (hashCodeAlreadyAtProbeLocation != currentHashCode) {
                  continue;
                }

                // we found our hash code - cache the entry bytes
                synchronized (hashFile) {
                  hashFile.seek(entryPositionAlreadyAtProbeLocation);
                  hashFile.read(fileBytes.array());
                }

                // read the key length
                long keyLength = !isAssociative ? FileOperations2.read(fileBytes, keySize, 0) : 0;

                // can't be our key since the key length doesn't match
                if (!isAssociative && keyLength != key.length) {
                  continue;
                }

                // read the data length
                long dataLength =
                    !isPrimitive ? read(fileBytes, valueSize, keySize.getSize()) : valueSize
                        .getSize();


                byte[] probedKey = new byte[(int) keyLength];
                byte[] data = new byte[(int) dataLength];

                int entrySize =
                    valueSize.getSize() + (!isPrimitive ? (int) dataLength : 0)
                        + (isAssociative ? 0 : keySize.getSize() + (int) keyLength);

                if (entrySize < FileOperations2.RANDOM_READ_BUFFER_LENGTH) {
                  // if the hash entry fits in our buffer, things are faster
                  fileBytes.position(keySize.getSize() + valueSize.getSize());
                  fileBytes.get(probedKey);

                  if (!isAssociative && !Arrays.equals(key, probedKey)) {
                    // not our key
                    continue;
                  }

                  fileBytes.get(data);
                } else {
                  synchronized (hashFile) {
                    hashFile.seek(entryPositionAlreadyAtProbeLocation + keySize.getSize()
                        + valueSize.getSize());
                    hashFile.readFully(probedKey);

                    if (!isAssociative && !Arrays.equals(key, probedKey)) {
                      // not our key
                      continue;
                    }

                    hashFile.readFully(data);
                  }
                }

                return data;
              }
            } catch (IOException e) {
              throw new RuntimeException("Error while finding key: " + e.getMessage(), e);
            }

            return null;
          }

          @Override
          public boolean hasNext() {
            return next != null;
          }

          @Override
          public byte[] next() {
            if (!hasNext()) {
              throw new IllegalStateException("next() called past end of iterator");
            }

            byte[] result = next;
            next = advance();

            return result;
          }

          @Override
          public void remove() {
            throw new UnsupportedOperationException("remove() not supported");
          }
        };
      }
    };
  }
}
