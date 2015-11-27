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

import java.io.BufferedInputStream;
import java.io.DataInput;
import java.io.DataInputStream;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicLong;

import org.sunnycode.hash.file2.ByteSize;
import org.sunnycode.hash.file2.HashEntry;

public class FileOperations2 {
  /** size of read buffer for iterator */
  public static final int ITERATOR_READ_BUFFER_LENGTH = 16 * 1024 * 1024; // 16MB

  /** size of read buffer for the random-access data file reads */
  public static final int RANDOM_READ_BUFFER_LENGTH = 4 * 1024; // 4KB

  /** size of write buffer for main data file */
  public static final int SEQUENTIAL_READ_BUFFER_SIZE = 16 * 1024 * 1024; // 16MB

  private final boolean isLargeFile;
  private final boolean isLargeCapacity;
  private final int slotSize;

  /** log base 2 of number of buckets */
  private final int bucketPower;

  /** total number of buckets */
  private final int buckets;

  private final int alignment = 2;

  private final ByteSize keySize;

  private final ByteSize valueSize;

  private final boolean isLongHash;

  private final boolean isAssociative;

  private final boolean isUuid;

  private final boolean isPrimitive;

  private final int hashSizeBytes;

  private final int positionSizeBytes;

  private final int bucketCountSizeBytes;

  private final Header2 header;

  protected FileOperations2(Header2 header, int bucketPower, int buckets, ByteSize keySize,
      ByteSize valueSize, boolean isLongHash, boolean isLargeCapacity, boolean isLargeFile,
      boolean isUuid, boolean isPrimitive) {
    this.header = header;
    this.bucketPower = bucketPower;
    this.buckets = buckets;
    this.keySize = keySize;
    this.valueSize = valueSize;
    this.isAssociative = ByteSize.ZERO.equals(keySize);
    this.isLongHash = isLongHash;
    this.isLargeCapacity = isLargeCapacity;
    this.isLargeFile = isLargeFile;
    this.isUuid = isUuid;
    this.isPrimitive = isPrimitive;

    this.hashSizeBytes = isLongHash ? 8 : 4;
    this.positionSizeBytes = isLargeFile ? 8 : 4;
    this.bucketCountSizeBytes = isLargeCapacity ? 8 : 4;

    this.slotSize = Calculations2.getBucketTableEntrySize(isLargeCapacity, isLargeFile);
  }

  public static FileOperations2 fromHeader(Header2 header) {
    return new FileOperations2(header, header.getBucketPower(), header.getBuckets(),
        header.getKeySize(), header.getValueSize(), header.isLongHash(), header.isLargeCapacity(),
        header.isLargeFile(), header.isUuid(), header.isPrimitive());
  }

  public void finish(long dataFilePosition, String dataFilePath, DataOutputStream dataFile,
      String radixFilePrefix, DataOutputStream[] hashCodeList, long[] bucketCounts)
      throws IOException, FileNotFoundException {
    if (header.isFinished()) {
      throw new IllegalStateException("HashFile finish() has already been called");
    }

    header.setFinished();

    dataFile.close();
    for (DataOutputStream stream : hashCodeList) {
      stream.close();
    }

    long[] bucketOffsets = Calculations2.computeBucketOffsets(bucketCounts);
    long pos = dataFilePosition;

    RandomAccessFile dataFileRandomAccess = new RandomAccessFile(dataFilePath, "rw");
    dataFileRandomAccess.seek(dataFilePosition);

    writeHashTable(radixFilePrefix, bucketOffsets, bucketCounts, dataFileRandomAccess);

    ByteBuffer slotTable =
        Calculations2.getBucketPositionTable(alignment, bucketOffsets, bucketCounts, pos,
            header.isLongHash(), header.isLargeFile(), header.isLargeCapacity());

    dataFileRandomAccess.seek(0L);
    header.write(dataFileRandomAccess);

    dataFileRandomAccess.write(slotTable.array());

    for (int i = 0; i < Calculations2.RADIX_FILE_COUNT; i++) {
      String filename = String.format("%s%02X", radixFilePrefix, i);
      (new File(filename)).delete();
    }

    dataFileRandomAccess.close();
  }

  public void writeHashEntry(DataOutputStream[] hashCodeList, long[] bucketCounts,
      long dataFilePosition, byte[] key) throws IOException {
    long hashValue = Calculations2.computeHash(key, isLongHash, isUuid);

    int radix = Calculations2.getRadix(hashValue, bucketPower);
    int bucket = Calculations2.getBucket(hashValue, bucketPower);

    write(hashCodeList[radix], isLongHash ? ByteSize.EIGHT : ByteSize.FOUR, hashValue);

    if ((dataFilePosition & 3) != 0) {
      throw new IllegalStateException("Offset into data file position must be multiple of 4 bytes");
    }

    write(hashCodeList[radix], isLargeFile ? ByteSize.EIGHT : ByteSize.FOUR,
        dataFilePosition >> alignment);

    bucketCounts[bucket]++;
  }

  public long writeKeyVaue(DataOutputStream dataFile, long pos, byte[] key, byte[] value)
      throws IOException {
    if (header.isFinished()) {
      throw new IllegalStateException("cannot add() to a finished hashFile");
    }

    this.header.incrementElementCount();

    // key length - non-primitive, non-associative hash files when key length byte size is > 0
    if (!isPrimitive && !isAssociative && !ByteSize.ZERO.equals(keySize)) {
      write(dataFile, keySize, key.length);
    }

    // value length - non-primitive hash files when value length byte size is > 0
    if (!isPrimitive && !ByteSize.ZERO.equals(valueSize)) {
      write(dataFile, valueSize, value.length);
    }

    // key bytes only appear in non-associative hash files
    if (!isAssociative) {
      dataFile.write(key);
    }

    // value bytes only appear in hash files when value length byte size > 0
    if (!ByteSize.ZERO.equals(valueSize)) {
      dataFile.write(value);
    }

    int paddingSize = 0;

    if (isPrimitive) {
      if (isAssociative) {
        paddingSize = writePadding(dataFile, ByteSize.ZERO, ByteSize.ZERO, 0, valueSize.getSize());
      } else {
        paddingSize =
            writePadding(dataFile, ByteSize.ZERO, ByteSize.ZERO, keySize.getSize(),
                valueSize.getSize());
      }
    } else {
      if (isAssociative) {
        paddingSize = writePadding(dataFile, keySize, valueSize, 0, value.length);
      } else {
        paddingSize = writePadding(dataFile, keySize, valueSize, key.length, value.length);
      }
    }

    long bytesWritten = 0;

    if (isPrimitive) {
      bytesWritten = (long) valueSize.getSize() + (long) paddingSize;

      if (!isAssociative) {
        bytesWritten += (long) keySize.getSize();
      }
    } else {
      bytesWritten = (long) valueSize.getSize() + (long) value.length + (long) paddingSize;

      if (!isAssociative) {
        bytesWritten += (long) keySize.getSize() + (long) key.length;
      }
    }

    return advanceBytes(pos, bytesWritten, isLargeFile);
  }

  public void readBucketEntries(ByteBuffer hashTableOffsets) {
    int slots = this.buckets;
    for (int i = 0; i < slots; i++) {
      getHashTablePosition(hashTableOffsets, i);
      getHashTableSize(hashTableOffsets, i);
    }
  }

  public long getEndOfData(RandomAccessFile in) throws IOException {
    in.seek(Header2.getBucketTableOffset());

    return read(in, isLargeFile ? ByteSize.EIGHT : ByteSize.FOUR) << alignment;
  }

  public HashEntry readHashEntry(final DataInputStream input, final AtomicLong pos) {
    try {
      int keyLength = 0;

      if (isPrimitive) {
        if (!isAssociative) {
          keyLength = header.getKeySize().getSize();
        } else {
          // associative - keylength is always zero
        }
      } else {
        if (!isAssociative) {
          keyLength = (int) read(input, header.getKeySize());
          pos.addAndGet(header.getKeySize().getSize());
        } else {
          // associative - keylength is always zero
        }
      }

      int dataLength = 0;

      if (isPrimitive) {
        dataLength = header.getValueSize().getSize();
      } else {
        dataLength = (int) read(input, header.getValueSize());
        pos.addAndGet(header.getValueSize().getSize());
      }

      byte[] key = new byte[0];

      if (keyLength > 0) {
        key = new byte[keyLength];
        input.readFully(key);
        pos.addAndGet(keyLength);
      }

      byte[] data = new byte[dataLength];

      input.readFully(data);
      pos.addAndGet(dataLength);

      int padding = 0;

      if (isPrimitive) {
        padding = 4 - ((keyLength + dataLength) % 4);
      } else {
        padding =
            4 - ((header.getKeySize().getSize() + header.getValueSize().getSize() + keyLength + dataLength) % 4);
      }

      if (padding == 4) {
        padding = 0;
      }

      input.read(new byte[padding]);
      pos.addAndGet(padding);

      return new HashEntry(key, data);
    } catch (IOException ioException) {
      throw new IllegalArgumentException("invalid HashFile format");
    }
  }

  public byte[] getFirst(RandomAccessFile hashFile, ByteBuffer hashTableOffsets, byte[] key) {
    if (hashFile == null) {
      throw new IllegalStateException("get() not allowed when HashFile is closed()");
    }

    if (isAssociative) {
      throw new UnsupportedOperationException(
          "get() not allowed for associative hash files, use getMulti() instead");
    }

    long currentHashCode = Calculations2.computeHash(key, isLongHash, isUuid);

    int innerSlot = Calculations2.getBucket(currentHashCode, bucketPower);
    int innerSlotBase = innerSlot * slotSize;

    long innerSlotBasePosition =
        (isLargeCapacity ? hashTableOffsets.getLong(innerSlotBase) : hashTableOffsets
            .getInt(innerSlotBase)) << alignment;

    int allSlotTablesBasePosition = this.bucketCountSizeBytes;

    long innerSlotTableSize =
        isLargeCapacity
            ? hashTableOffsets.getLong(allSlotTablesBasePosition + innerSlotBase)
            : hashTableOffsets.getInt(allSlotTablesBasePosition + innerSlotBase);

    if (innerSlotTableSize == 0) {
      return null;
    }

    int innerSlotIndexToProbe = (int) (Math.abs(currentHashCode) % innerSlotTableSize);

    ByteBuffer innerSlotTableBytes =
        ByteBuffer.allocate(Calculations2.getHashTableEntrySize(isLongHash, isLargeFile)
            * ((int) innerSlotTableSize));

    ByteBuffer fileBytes = ByteBuffer.allocate(RANDOM_READ_BUFFER_LENGTH);

    int hashEntrySize = Calculations2.getHashTableEntrySize(isLongHash, isLargeFile);

    try {
      synchronized (hashFile) {
        hashFile.seek(innerSlotBasePosition);
        hashFile.readFully(innerSlotTableBytes.array());
      }

      long searchTrials = 0;

      while (searchTrials < innerSlotTableSize) {
        int probeLocation = innerSlotIndexToProbe * hashEntrySize;

        long hashCodeAlreadyAtProbeLocation =
            isLongHash ? innerSlotTableBytes.getLong(probeLocation) : innerSlotTableBytes
                .getInt(probeLocation);

        long entryPositionAlreadyAtProbeLocation =
            (isLargeFile
                ? innerSlotTableBytes.getLong(probeLocation + this.hashSizeBytes)
                : innerSlotTableBytes.getInt(probeLocation + this.hashSizeBytes)) << alignment;

        // if we find an empty location, we can break early because
        // the hash code should have been in the earliest spot
        if (entryPositionAlreadyAtProbeLocation == 0) {
          return null;
        }

        searchTrials += 1;
        innerSlotIndexToProbe += 1;

        // wrap around if the index passes the table size
        if (innerSlotIndexToProbe >= innerSlotTableSize) {
          innerSlotIndexToProbe = 0;
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
        long keyLength = isAssociative ? 0 : read(fileBytes, keySize, 0);

        // can't be our key since the key length doesn't match
        if (!isAssociative && keyLength != key.length) {
          continue;
        }

        // read the data length
        long dataLength =
            !isPrimitive ? read(fileBytes, valueSize, keySize.getSize()) : valueSize.getSize();

        byte[] probedKey = new byte[(int) keyLength];
        byte[] data = new byte[(int) dataLength];

        int entrySize =
            valueSize.getSize() + (!isPrimitive ? (int) dataLength : 0)
                + (isAssociative ? 0 : keySize.getSize() + (int) keyLength);

        if (entrySize < RANDOM_READ_BUFFER_LENGTH) {
          // if the hash entry fits in our buffer, things are faster
          fileBytes.position(keySize.getSize() + valueSize.getSize());
          fileBytes.get(probedKey);

          if (!isAssociative && !Arrays.equals(key, probedKey)) {
            // not our key
            continue;
          }

          fileBytes.get(data);
        } else {
          // if the hash entry doesn't fit in our buffer, read it from the file
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

  public Iterable<byte[]> getMulti(final RandomAccessFile hashFile,
      final ByteBuffer hashTableOffsets, final byte[] key) {
    if (hashFile == null) {
      throw new IllegalStateException("get() not allowed when HashFile is closed()");
    }

    return Iterators2.getMultiIterable(alignment, hashFile, hashTableOffsets, bucketPower,
        slotSize, keySize, valueSize, isAssociative, isLongHash, isLargeCapacity, isLargeFile,
        isUuid, isPrimitive, key);
  }

  /** Writes out a merged hash table file from all of the radix files */
  private void writeHashTable(String radixFilePrefix, long[] bucketStarts, long[] bucketCounts,
      DataOutput hashTableFile) throws IOException {
    int longPointerSize = Calculations2.getHashTableEntrySize(isLongHash, isLargeFile);

    for (int i = 0; i < Calculations2.RADIX_FILE_COUNT; i++) {
      File radixFile = new File(getRadixFileName(radixFilePrefix, i));
      long radixFileLength = radixFile.length();

      /*
       * FIXME : int number of entries implies a limit of 32 billion entries (2GB / 16bytes = 128MM,
       * 128MM * 256 = 32BN); this is a property of ByteBuffer only being able to allocate 2GB
       */
      if (radixFileLength > Integer.MAX_VALUE) {
        throw new RuntimeException("radix file too huge (" + radixFileLength + ")");
      }

      int entries = (int) radixFileLength / longPointerSize;

      if (entries < 1) {
        continue;
      }

      try (final DataInputStream radixFileLongs =
          new DataInputStream(new BufferedInputStream(new FileInputStream(radixFile),
              SEQUENTIAL_READ_BUFFER_SIZE))) {

        ByteBuffer hashTableBytes = ByteBuffer.allocate((int) radixFileLength);

        populateHashTable(bucketStarts, bucketCounts, longPointerSize, entries, radixFileLongs,
            hashTableBytes);

        hashTableFile.write(hashTableBytes.array());
      }
    }
  }

  private void populateHashTable(long[] bucketStarts, long[] bucketCounts, int longPointerSize,
      int entries, final DataInputStream radixFileLongs, ByteBuffer hashTableBytes)
      throws IOException {
    // for each hash table entry
    for (int j = 0; j < entries; j++) {
      // read the 4-byte or 8-byte hash code
      long hashCode = isLongHash ? radixFileLongs.readLong() : radixFileLongs.readInt();
      // read the 4-byte or 8-byte long file offset
      long position = isLargeFile ? radixFileLongs.readLong() : radixFileLongs.readInt();

      int outerSlot = Calculations2.getBucket(hashCode, bucketPower);
      int innerSlot = Calculations2.getBaseBucketForHash(hashCode, bucketPower);

      int outerSlotStart = (int) bucketStarts[outerSlot];
      int innerSlotStart = (int) bucketStarts[innerSlot];
      int relativeInnerSlotStart = (int) (outerSlotStart - innerSlotStart);
      int innerSlotSize = (int) bucketCounts[innerSlot];


      int innerSlotHashProbe = (int) (Math.abs(hashCode) % innerSlotSize);
      int innerSlotHashIndex = relativeInnerSlotStart + innerSlotHashProbe;

      boolean finished = false;
      int trials = 0;

      while (!finished && trials < innerSlotSize) {
        trials += 1;
        int probedHashCodeIndex = (innerSlotHashIndex * longPointerSize);
        int probedPositionIndex = probedHashCodeIndex + hashSizeBytes;

        hashTableBytes.position(0);

        long hashCodeAlreadyAtProbePosition =
            isLargeCapacity ? hashTableBytes.getLong(probedPositionIndex) : hashTableBytes
                .getInt(probedPositionIndex);

        boolean notCollision = (hashCodeAlreadyAtProbePosition == 0);

        if (notCollision) {
          if (isLongHash) {
            hashTableBytes.putLong(probedHashCodeIndex, hashCode);
          } else {
            hashTableBytes.putInt(probedHashCodeIndex, (int) hashCode);
          }

          if (isLargeFile) {
            hashTableBytes.putLong(probedPositionIndex, position);
          } else {
            hashTableBytes.putInt(probedPositionIndex, (int) position);
          }

          finished = true;
        } else {
          if (innerSlotSize == 1) {
            throw new RuntimeException("shouldn't happen: collision in bucket of size 1!");
          }

          innerSlotHashIndex += 1;

          if (innerSlotHashIndex >= (relativeInnerSlotStart + innerSlotSize)) {
            innerSlotHashIndex = relativeInnerSlotStart;
          }
        }
      }
    }
  }

  /**
   * Get the long offset (in bytes) into the HashFile2 of the specified hash table slot.
   * 
   * @param bucketData
   * @param slotIndex
   * @return
   */
  private long getHashTablePosition(ByteBuffer bucketData, int slotIndex) {
    int offset = slotIndex * slotSize;

    return (isLargeFile ? bucketData.getLong(offset) : bucketData.getInt(offset)) << alignment;
  }

  /**
   * Get the size (in bytes) of the specified hash table slot.
   * 
   * @param bucketData
   * @param slotIndex
   * @return
   */
  private long getHashTableSize(ByteBuffer bucketData, int slotIndex) {
    int offset = (slotIndex * slotSize) + positionSizeBytes;

    return isLargeCapacity ? bucketData.getLong(offset) : bucketData.getInt(offset);
  }

  /**
   * Write the appropriate amount of zero-byte padding to the file so that entries are aligned to
   * 4-byte boundaries.
   * 
   * @param dataFile
   * @param keySize
   * @param valueSize
   * @param keyLen
   * @param valueLen
   * @return
   * @throws IOException
   */
  private static int writePadding(DataOutputStream dataFile, ByteSize keySize, ByteSize valueSize,
      int keyLen, int valueLen) throws IOException {
    int paddingSize = 4 - ((keySize.getSize() + valueSize.getSize() + keyLen + valueLen) % 4);

    paddingSize = (paddingSize < 4) ? paddingSize : 0;

    if (paddingSize > 0) {
      dataFile.write(new byte[paddingSize]);
    }

    return paddingSize;
  }

  /**
   * Returns the hash list file name String corresponding to index i.
   */
  private static String getRadixFileName(String radixFilePrefix, int i) {
    return String.format("%s%02X", radixFilePrefix, i);
  }

  /**
   * Advances the file pointer by <code>count</code> bytes, throwing an exception if the postion has
   * exhausted a long (hopefully not likely).
   */
  private static long advanceBytes(long pos, long count, boolean isLongPos) throws IOException {
    long newpos = pos + count;
    if (newpos < count || (!isLongPos && newpos > Integer.MAX_VALUE))
      throw new IOException("HashFile is too big.");
    return newpos;
  }

  /**
   * Write an integer value to the specified DataOutput using the specified number of bytes. The
   * long value is cast to the integer datatype of the given size before writing.
   * 
   * @param out
   * @param size
   * @param value
   * @throws IOException
   */
  private static void write(DataOutput out, ByteSize size, long value) throws IOException {
    switch (size) {
      case EIGHT:
        out.writeLong(value);
        break;
      case FOUR:
        if (value > Integer.MAX_VALUE) {
          throw new IOException("Integer overflow : " + value);
        }
        out.writeInt((int) value);
        break;
      case TWO:
        if (value > Character.MAX_VALUE) {
          throw new IOException("Character overflow : " + value);
        }
        out.writeChar((int) value);
        break;
      case ONE:
        if (value > Byte.MAX_VALUE) {
          throw new IOException("Byte overflow : " + value);
        }
        out.writeByte((int) value);
        break;
      case ZERO:
        if (value > 0) {
          throw new IOException("Expected empty value!" + value);
        }
        break;
    }
  }

  /**
   * Read an integer value using the specified number of bytes from the DataInput at the current
   * offset, casting the result to a long.
   * 
   * @param in
   * @param size
   * @return
   * @throws IOException
   */
  public static long read(DataInput in, ByteSize size) throws IOException {
    switch (size) {
      case EIGHT:
        return in.readLong();
      case FOUR:
        return in.readInt();
      case TWO:
        return in.readChar();
      case ONE:
        return in.readByte();
      case ZERO:
        return 0;
      default:
        throw new IllegalArgumentException("Unknown ByteSize: " + size);
    }
  }

  /**
   * Read an integer value using the specified number of bytes from the DataInput at the given
   * offset, casting the result to a long.
   * 
   * @param in
   * @param size
   * @param pos
   * @return
   * @throws IOException
   */
  public static long read(ByteBuffer in, ByteSize size, int pos) throws IOException {
    switch (size) {
      case EIGHT:
        return in.getLong(pos);
      case FOUR:
        return in.getInt(pos);
      case TWO:
        return in.getChar(pos);
      case ONE:
        return in.get(pos);
      case ZERO:
        return 0;
      default:
        throw new IllegalArgumentException("Unknown ByteSize: " + size);
    }
  }
}
