import re
import os.path


isALetterRegex = re.compile(r"[a-z]", re.IGNORECASE)
alphabetSize = 26

# matches words and contractions
extractWordsRegex = re.compile(r"\b((?<!')[\w-]+('\w*)?)|([\w-]+)\b", re.IGNORECASE)


def encrypt(plaintext: str, n: int):
    """
    shifts the letters to the right 'n' times
    """
    cipher = ""

    for char in plaintext:
        # check if the char is a letter
        if isALetterRegex.search(char) is not None:
            baseValue = ord('a')
            asciiValue = ord(char)

            # handle uppercase letters
            if asciiValue < baseValue:
                baseValue = ord('A')

            # shift the character by 'n' letters
            char = chr((asciiValue + n - baseValue) % alphabetSize + baseValue)

        cipher += char

    return cipher


def decrypt(cipher: str, n: int):
    """
    shifts the letters to the left 'n' times
    """
    plaintext = ""

    for char in cipher:
        # check if the char is a letter
        if isALetterRegex.search(char) is not None:
            baseValue = ord('a')
            asciiValue = ord(char)

            # handle uppercase letters
            if asciiValue < baseValue:
                baseValue = ord('A')

            # shift the character by 'n' letters
            char = chr((asciiValue - n - baseValue) % alphabetSize + baseValue)

        plaintext += char

    return plaintext


def bruteForceAnyOccurrence(cipher: str, vocabulary: str):
    """
    brute force by checking if any cipher word appears *anywhere* in the encrypted vocab

    string split is used to extract words

    *anywhere* meaning the word can be a substring of another larger word which may be unwanted
    """

    # make a set of words out of the ciphertext
    # the case of the letters does not matter, but all letters are the same case to possibly reduce the set size
    cipherWordSet = set(cipher.lower().split())

    # lowercase the vocab to ignore case while finding a substring
    vocabulary = vocabulary.lower()

    # loop through all the possible cipher keys
    # it starts at zero bc the ciphertext could already be the plaintext
    for n in range(alphabetSize):
        encryptedVocabulary = encrypt(vocabulary, n)

        # check if any cipher word appears *anywhere* in the vocab
        # *anywhere* meaning the word can be a substring of another larger word which may be unwanted
        for cipherWord in cipherWordSet:
            if encryptedVocabulary.find(cipherWord) != -1:
                plaintext = decrypt(cipher, n)
                return plaintext, n

    print("\nThe key could not be found")

    # return the cipher if the plaintext could not be found with the provided vocabulary
    return cipher, 0


def bruteForceSingleOccurrenceSplit(cipher: str, vocabulary: str):
    """
    brute force by matching cipher words (extracted using string split) to the vocabulary that has been encrypted

    the first matching result is returned
    matching is determined by whether a single cipher word is in the vocab set or if the cipher regex matches the encrypted vocab

    falls back on to matching any subtring occurrence of the cipher vocab words
    """

    # make a set of words out of the ciphertext
    # the case of the letters does not matter, but all letters are the same case to possibly reduce the set size
    cipherWords = cipher.split()
    cipherWords = list(set([word.lower() for word in cipherWords]))
    cipherRegexWords = ["(\\b" + re.escape(word) + "\\b)" for word in cipherWords]

    # make a set of words out of the vocab
    # the case of the letters does not matter, but all letters are the same case to possibly reduce the set size
    vocabWords = vocabulary.split()
    vocabWords = set([word.lower() for word in vocabWords])

    # loop through all the possible cipher keys
    # it starts at zero bc the ciphertext could already be the plaintext
    for n in range(alphabetSize):
        encryptedVocabulary = encrypt(vocabulary, n)
        encryptedVocabularySet = set([encrypt(vocabWord, n) for vocabWord in vocabWords])

        # check if any cipher words matches the vocab
        for x in range(len(cipherWords)):
            if (cipherWords[x] in encryptedVocabularySet) or (re.search(cipherRegexWords[x], encryptedVocabulary, re.IGNORECASE) is not None):
                plaintext = decrypt(cipher, n)
                return plaintext, n

    # look for any occurrence as a fallback
    return bruteForceAnyOccurrence(cipher, vocabulary)


def bruteForceSingleOccurrence(cipher: str, vocabulary: str):
    """
    brute force by matching cipher words (extracted using regex) to the vocabulary that has been encrypted

    the first matching result is returned
    matching is determined by whether a single cipher word is in the vocab set or if the cipher regex matches the encrypted vocab

    falls back on to matching any subtring occurrence of the cipher vocab words
    """

    # make a set of words out of the ciphertext
    # the case of the letters does not matter, but all letters are the same case to possibly reduce the set size
    cipherWords = extractWordsRegex.findall(cipher)
    cipherWords = list(set([word[0].lower() for word in cipherWords]))
    cipherRegexWords = ["(\\b" + re.escape(word) + "\\b)" for word in cipherWords]

    # make a set of words out of the vocab
    # the case of the letters does not matter, but all letters are the same case to possibly reduce the set size
    vocabWords = extractWordsRegex.findall(vocabulary)
    vocabWords = set([word[0].lower() for word in vocabWords])

    # loop through all the possible cipher keys
    # it starts at zero bc the ciphertext could already be the plaintext
    for n in range(alphabetSize):
        encryptedVocabulary = encrypt(vocabulary, n)
        encryptedVocabularySet = set([encrypt(vocabWord, n) for vocabWord in vocabWords])

        # check if any cipher words matches the vocab
        for x in range(len(cipherWords)):
            if (cipherWords[x] in encryptedVocabularySet) or (re.search(cipherRegexWords[x], encryptedVocabulary, re.IGNORECASE) is not None):
                plaintext = decrypt(cipher, n)
                return plaintext, n

    # look for any occurrence as a fallback
    return bruteForceSingleOccurrenceSplit(cipher, vocabulary)


def bruteForceSplit(cipher: str, vocabulary: str):
    """
    brute force by matching all cipher words to the vocab words using basic string splitting and sets

    falls back on to matching any single occurrence of the cipher words in the vocab
    """

    cipherWords = cipher.split()
    cipherWords = set([word.lower() for word in cipherWords])

    # make a set of words out of the vocab
    # the case of the letters does not matter, but all letters are the same case to possibly reduce the set size
    vocabWords = vocabulary.split()
    vocabWords = set([word.lower() for word in vocabWords])

    # loop through all the possible cipher keys
    # it starts at zero bc the ciphertext could already be the plaintext
    for n in range(alphabetSize):
        encryptedVocabulary = set([encrypt(vocabWord, n) for vocabWord in vocabWords])

        # check if the cipher words are in the encrypted vocab words
        if cipherWords.issubset(encryptedVocabulary) or encryptedVocabulary.issubset(cipherWords):
            plaintext = decrypt(cipher, n)
            return plaintext, n

    # look for encrypted vocab words in the ciphertext as a fallback
    return bruteForceSingleOccurrence(cipher, vocabulary)


def bruteForce(cipher: str, vocabulary: str):
    """
    brute force by matching all cipher words to the vocab words using regex and sets

    falls back on other matching variations
    """

    # make a set of words out of the ciphertext
    # the case of the letters does not matter, but all letters are the same case to possibly reduce the set size
    cipherWords = extractWordsRegex.findall(cipher)
    cipherWords = set([word[0].lower() for word in cipherWords])

    # make a set of words out of the vocab
    # the case of the letters does not matter, but all letters are the same case to possibly reduce the set size
    vocabWords = extractWordsRegex.findall(vocabulary)
    vocabWords = set([word[0].lower() for word in vocabWords])

    # loop through all the possible cipher keys
    # it starts at zero bc the ciphertext could already be the plaintext
    for n in range(alphabetSize):
        encryptedVocabulary = set([encrypt(vocabWord, n) for vocabWord in vocabWords])

        # check if the cipher words are in the encrypted vocab words
        if cipherWords.issubset(encryptedVocabulary) or encryptedVocabulary.issubset(cipherWords):
            plaintext = decrypt(cipher, n)
            return plaintext, n

    # try some matching variations as a fallback
    return bruteForceSplit(cipher, vocabulary)


def main():
    # command handler
    while True:
        print("Type the number of the command to execute the command:")
        print("\t1) encrypt a message")
        print("\t2) decrypt a message")
        print("\t3) brute force a message")
        print("\t4) quit")

        selection = input()

        # command 1
        if selection == "1":
            plaintext = input("What is the plaintext message?\n")
            key = input("What is the key? (The number of letters to shift the plaintext message by)\n")

            try:
                key = int(key)

                if (key >= 0):
                    print("\nEncrypted Message:\n" + encrypt(plaintext, key))
                else:
                    print("Please use a positive integer as the key")
            except:
                print("Please use a positive integer as the key")

        # command 2
        elif selection == "2":
            cipher = input("What is the ciphertext message?\n")
            key = input("What is the key? (The number of letters to shift the ciphertext message by)\n")

            try:
                key = int(key)

                if (key >= 0):
                    print("\nDecrypted Message:\n" + decrypt(cipher, key))
                else:
                    print("Please use a positive integer as the key")
            except:
                print("Please use a positive integer as the key")

        # command 3
        elif selection == "3":
            cipher = input("What is the ciphertext message?\n")
            vocabFile = input("What is the full name of the vocabulary file?\nex: \"vocab.txt\"\n*** If the file has unicode characters, brute forcing may not work correctly ***\n")

            if os.path.isfile(vocabFile):
                with open(vocabFile) as vocab:
                    plaintext, key = bruteForce(cipher, vocab.read())
                    print("\nKey:\n" + str(key) + "\nDecrypted Message:\n" + plaintext)
            else:
                print("That file was not found")

        # command 4
        elif selection == "4":
            print("Goodbye!")
            return

        # unknown command
        else:
            print("That is not a command")

        print()


if __name__ == "__main__":
    main()
