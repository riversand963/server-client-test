# makkefile begins
# define a variable for compiler flags (JFLAGS)
# define a variable for the compiler (JC)  
# define a variable for the Java Virtual Machine (JVM)
# define a variable for a parameter. When you run make, you could use:
# make run FILE="Algo.csv" para sobre escribir el valor de FILE. 

HADOOP_CLASSPATH=/Users/yanqin/Workspace/hadoop-dev/hadoop-dist/target/hadoop-2.7.5/share/hadoop/common/lib/*:/Users/yanqin/Workspace/hadoop-dev/hadoop-dist/target/hadoop-2.7.5/share/hadoop/common/*:/Users/yanqin/Workspace/hadoop-dev/hadoop-dist/target/hadoop-2.7.5/share/hadoop/hdfs:/Users/yanqin/Workspace/hadoop-dev/hadoop-dist/target/hadoop-2.7.5/share/hadoop/hdfs/lib/*:/Users/yanqin/Workspace/hadoop-dev/hadoop-dist/target/hadoop-2.7.5/share/hadoop/hdfs/*:/Users/yanqin/Workspace/hadoop-dev/hadoop-dist/target/hadoop-2.7.5/share/hadoop/yarn/lib/*:/Users/yanqin/Workspace/hadoop-dev/hadoop-dist/target/hadoop-2.7.5/share/hadoop/yarn/*:/Users/yanqin/Workspace/hadoop-dev/hadoop-dist/target/hadoop-2.7.5/share/hadoop/mapreduce/lib/*:/Users/yanqin/Workspace/hadoop-dev/hadoop-dist/target/hadoop-2.7.5/share/hadoop/mapreduce/*:/contrib/capacity-scheduler/*.jar
CLASSPATH=.:${HOME}/Workspace/apache-log4j-1.2.17/*:${HADOOP_CLASSPATH}

#JFLAGS = -g
JFLAGS = -Xlint
JC = javac
JVM= java 
FILE=
# keystore is the name of the keystore file, while truststore is the trust store name
# SERVER_JVM_PROPS = -Djavax.net.ssl.keyStore=keystore -Djavax.net.ssl.keyStorePassword=123456
# CLIENT_JVM_PROPS = -Djavax.net.ssl.trustStore=turststore

#
# Clear any default targets for building .class files from .java files; we 
# will provide our own target entry to do this in this makefile.
# make has a set of default targets for different suffixes (like .c.o) 
# Currently, clearing the default for .java.class is not necessary since 
# make does not have a definition for this target, but later versions of 
# make may, so it doesn't hurt to make sure that we clear any default 
# definitions for these
#

.SUFFIXES: .java .class


#
# Here is our target entry for creating .class files from .java files 
# This is a target entry that uses the suffix rule syntax:
#	DSTS:
#		rule
# DSTS (Dependency Suffix     Target Suffix)
# 'TS' is the suffix of the target file, 'DS' is the suffix of the dependency 
#  file, and 'rule'  is the rule for building a target	
# '$*' is a built-in macro that gets the basename of the current target 
# Remember that there must be a < tab > before the command line ('rule') 
#

.java.class:
	$(JC) -cp $(CLASSPATH) $(JFLAGS) $*.java


#
# CLASSES is a macro consisting of N words (one for each java source file)
# When a single line is too long, use \<return> to split lines that then will be
# considered as a single line. For example:
# NAME = Camilo \
         Juan 
# is understood as
# NAME = Camilo        Juan

CLASSES = \
	AppConnection.java \
	GssServer.java \
	GssClient.java \
	HdfsSecurityUtils.java \
	Jaas.java \
	JsseClient.java \
	JsseServer.java \
	KerberosTlsEchoClient.java \
	KerberosTlsEchoServer.java \
	SaslGssapiTlsEchoServer.java \
	SaslGssapiTlsEchoClient.java \
	SaslTestClient.java \
	SaslTestServer.java \
	SimpleCacheClient.java \
	SimpleCacheServer.java \
	SimpleEchoClient.java \
	SimpleEchoServer.java \
	SimpleEchoServerProcess.java

#
# MAIN is a variable with the name of the file containing the main method
#

MAIN = SimpleEchoServerProcess

#
# the default make target entry
# for this example it is the target classes

default: classes


# Next line is a target dependency line
# This target entry uses Suffix Replacement within a macro: 
# $(macroname:string1=string2)
# In the words in the macro named 'macroname' replace 'string1' with 'string2'
# Below we are replacing the suffix .java of all words in the macro CLASSES 
# with the .class suffix
#

classes: $(CLASSES:.java=.class)


# Next two lines contain a target for running the program
# Remember the tab in the second line.
# $(JMV) y $(MAIN) are replaced by their values

run: $(MAIN).class
	$(JVM) -cp $(CLASSPATH) $(MAIN)

# this line is to remove all unneeded files from
# the directory when we are finished executing(saves space)
# and "cleans up" the directory of unneeded .class files
# RM is a predefined macro in make (RM = rm -f)
#

clean:
	$(RM) *.class
