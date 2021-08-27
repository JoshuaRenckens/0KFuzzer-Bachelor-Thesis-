// Fuzzer.cpp
// Main driver for FormatFuzzer

#include <unordered_map>
#include <stdlib.h>
#include <cstdio>
#include <cstring>
#include <cassert>
#include <getopt.h>
#include <stdint.h>
#include <climits>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <string>

#include "config.h"
#include "formatfuzzer.h"
#include "iostream"
#include <tuple>
#include <map>
#include <list>
#include <algorithm>

static const char *bin_name = "formatfuzzer";

extern bool get_parse_tree;
extern bool debug_print;

// Each command comes as if it were invoked from the command line

// fuzz - generate random inputs
int fuzz(int argc, char **argv)
{
	const char *decision_source = "/dev/urandom";

	// Process options
	while (1)
	{
		static struct option long_options[] =
			{
				{"help", no_argument, 0, 'h'},
				{"decisions", required_argument, 0, 'd'},
				{0, 0, 0, 0}};
		int option_index = 0;
		int c = getopt_long(argc, argv, "d:p",
							long_options, &option_index);

		// Detect the end of the options.
		if (c == -1)
			break;

		switch (c)
		{
		case 'h':
		case '?':
			fprintf(stderr, "fuzz: usage: fuzz [--decisions SOURCE] [FILES...|-]\n");
			fprintf(stderr, "Outputs random data to given FILES (or `-' for standard output).\n");
			fprintf(stderr, "Options:\n");
			fprintf(stderr, "--decisions SOURCE: Use SOURCE for generation decisions (default %s)\n", decision_source);
			fprintf(stderr, "-p: print parse tree\n");
			return 0;

		case 'd':
			decision_source = optarg;
			break;
		case 'p':
			get_parse_tree = true;
			break;
		}
	}
    
    if (optind >= argc) {
		fprintf(stderr, "%s: missing output files. (Use '-' for standard output)\n", bin_name);
        return 1;
    }

	// Main function
	int errors = 0;
	for (int arg = optind; arg < argc; arg++)
	{
		char *out = argv[arg];
		bool success = false;
		setup_input(decision_source);
		try
		{
			generate_file();
			success = true;
		}
		catch (int status)
		{
			delete_globals();
			if (status == 0)
				success = true;
		}
		catch (...)
		{
			delete_globals();
		}
		save_output(out);
		if (success)
			fprintf(stderr, "%s: %s created\n", bin_name, out);
		else
		{
			fprintf(stderr, "%s: %s failed\n", bin_name, out);
			errors++;
		}
	}

	return errors;
}

// fuzz - parse existing files
int parse(int argc, char **argv)
{
	const char *decision_sink = 0;

	// Process options
	while (1)
	{
		static struct option long_options[] =
			{
				{"help", no_argument, 0, 'h'},
				{"decisions", required_argument, 0, 'd'},
				{0, 0, 0, 0}};
		int option_index = 0;
		int c = getopt_long(argc, argv, "d:",
							long_options, &option_index);

		// Detect the end of the options.
		if (c == -1)
			break;

		switch (c)
		{
		case 'h':
		case '?':
			fprintf(stderr, "parse: usage: parse [--decisions SINK] [FILES...|-]\n");
			fprintf(stderr, "Parses given FILES (or `-' for standard input).\n");
			fprintf(stderr, "Options:\n");
			fprintf(stderr, "--decisions SINK: Save parsing decisions in SINK (default: none)\n");
			return 0;

		case 'd':
			decision_sink = optarg;
			break;
		}
	}
    
    if (optind >= argc) {
		fprintf(stderr, "%s: missing input files. (Use '-' for standard input.)\n", bin_name);
        return 1;
    }

	int errors = 0;
	for (int arg = optind; arg < argc; arg++)
	{
		char *in = argv[arg];
		bool success = false;

		set_parser();
		setup_input(in);
		try
		{
			generate_file();
			success = true;
		}
		catch (int status)
		{
			delete_globals();
			if (status == 0)
				success = true;
		}
		catch (...)
		{
			delete_globals();
		}
		if (success)
			fprintf(stderr, "%s: %s parsed\n", bin_name, in);
		else
		{
			fprintf(stderr, "%s: %s failed\n", bin_name, in);
			errors++;
		}

		if (decision_sink)
			save_output(decision_sink);
	}

	return errors;
}

extern "C" size_t afl_pre_save_handler(unsigned char* data, size_t size, unsigned char** new_data);
extern "C" int afl_post_load_handler(unsigned char* data, size_t size, unsigned char** new_data, size_t* new_size);
extern bool print_errors;
extern std::unordered_map<std::string, std::string> variable_types;

unsigned copy_rand(unsigned char *dest);

extern const char* chunk_name;
extern int file_index;

extern bool get_chunk;
extern bool get_all_chunks;
extern bool smart_mutation;
extern unsigned chunk_start;
extern unsigned chunk_end;
extern unsigned rand_start;
extern unsigned rand_end;
extern bool is_optional;
extern bool is_delete;
extern bool following_is_optional;


/* Get unix time in microseconds */

static uint64_t get_cur_time_us(void) {

  struct timeval  tv;
  struct timezone tz;

  gettimeofday(&tv, &tz);

  return (tv.tv_sec * 1000000ULL) + tv.tv_usec;

}

void write_file(const char* filename, unsigned char* data, size_t size) {
	printf("Saving file %s\n", filename);
	int file_fd = open(filename, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
	ssize_t res = write(file_fd, data, size);
	assert((size_t) res == size);
	close(file_fd);
}

// smart_replace - apply a smart replacement
int smart_replace(int argc, char **argv)
{
	char *file_t = NULL;
	int start_t = -1;
	int end_t = -1;
	bool optional_t = false;
	const char* chunk_t;
	char *file_s = NULL;
	int start_s = -1;
	int end_s = -1;
	bool optional_s = false;
	const char* chunk_s;

	bool success = false;

	unsigned char *rand_t = new unsigned char[MAX_RAND_SIZE];
	unsigned char *rand_s = new unsigned char[MAX_RAND_SIZE];
	unsigned len_t;
	int rand_fd = open("/dev/urandom", O_RDONLY);
	ssize_t r = read(rand_fd, rand_t, MAX_RAND_SIZE);
	if (r != MAX_RAND_SIZE)
		printf("Read only %ld bytes from /dev/urandom\n", r);
	close(rand_fd);
	// Process options
	while (1)
	{
		static struct option long_options[] =
			{
				{"help", no_argument, 0, 'h'},
				{"targetfile", required_argument, 0, 1},
				{"targetstart", required_argument, 0, 2},
				{"targetend", required_argument, 0, 3},
				{"sourcefile", required_argument, 0, 4},
				{"sourcestart", required_argument, 0, 5},
				{"sourceend", required_argument, 0, 6},
				{0, 0, 0, 0}};
		int option_index = 0;
		int c = getopt_long(argc, argv, "",
							long_options, &option_index);

		// Detect the end of the options.
		if (c == -1)
			break;

		switch (c)
		{
		case 'h':
		case '?':
			fprintf(stderr, R"(replace: Smart Replacement
replace --targetfile file_t --targetstart start_t --targetend end_t
        --sourcefile file_s --sourcestart start_s --sourceend end_s OUTFILE
			
Apply a smart mutation which replaces one chunk from file_t (byte range
[start_t, end_t]) with another chunk from file_s (byte range [start_s, end_s]).
The resulting file should be similar to file_t, except with the source chunk
from file_s copied into the appropriate position of the target chunk from
file_t.  Moreover, the mutation is smarter than simple memmove() operations,
which should allow it to fix constraints implemented in the binary template,
such as lenght fields and checksums.  Command returns 0 if mutation worked as
expected or nonzero if it didn't work as expected.  This happens when the chunk
from file_s doesn't fit well in file_t because it required a larger or smaller
number of decision bytes in file_t than it did in file_s.
)");
			return 0;

		case 1:
			file_t = optarg;
			break;
		case 2:
			start_t = strtol(optarg, NULL, 0);
			break;
		case 3:
			end_t = strtol(optarg, NULL, 0);
			break;
		case 4:
			file_s = optarg;
			break;
		case 5:
			start_s = strtol(optarg, NULL, 0);
			break;
		case 6:
			end_s = strtol(optarg, NULL, 0);
			break;
		}
	}
    
	if (optind >= argc) {
		fprintf(stderr, "%s: missing output file.\n", bin_name);
		return -2;
	}
	if (!file_t || start_t == -1 || end_t == -1) {
		fprintf(stderr, "%s: missing required arguments for target file.\n", bin_name);
		return -2;
	}
	if (!file_s || start_s == -1 || end_s == -1) {
		fprintf(stderr, "%s: missing required arguments for source file.\n", bin_name);
		return -2;
	}

	// Main function
	char *out = argv[optind];

	printf("Parsing file %s\n\n", file_s);
	success = false;

	get_chunk = true;
	chunk_start = start_s;
	chunk_end = end_s;
	rand_start = rand_end = UINT_MAX;
	set_parser();
	setup_input(file_s);
	try
	{
		generate_file();
		success = true;
	}
	catch (int status)
	{
		delete_globals();
		if (status == 0)
			success = true;
	}
	catch (...)
	{
		delete_globals();
	}
	if (!success)
	{
		fprintf(stderr, "%s: Parsing %s failed\n", bin_name, file_s);
		return -2;
	}
	if (rand_start == UINT_MAX) {
		fprintf(stderr, "%s: Unable to find chunk in file %s\n", bin_name, file_s);
		return -2;
	}
	copy_rand(rand_s);
	start_s = rand_start;
	end_s = rand_end;
	optional_s = is_optional;
	chunk_s = chunk_name;


	printf("\nParsing file %s\n\n", file_t);
	success = false;

	get_chunk = true;
	chunk_start = start_t;
	chunk_end = end_t;
	rand_start = rand_end = UINT_MAX;
	set_parser();
	setup_input(file_t);
	try
	{
		generate_file();
		success = true;
	}
	catch (int status)
	{
		delete_globals();
		if (status == 0)
			success = true;
	}
	catch (...)
	{
		delete_globals();
	}
	if (!success)
	{
		fprintf(stderr, "%s: Parsing %s failed\n", bin_name, file_t);
		return -2;
	}
	if (end_t != -1 && rand_start == UINT_MAX) {
		fprintf(stderr, "%s: Unable to find chunk in file %s\n", bin_name, file_t);
		return -2;
	}
	len_t = copy_rand(rand_t);
	start_t = rand_start;
	end_t = rand_end;
	optional_t = is_optional;
	chunk_t = chunk_name;

	if (optional_t && !optional_s) {
		fprintf(stderr, "%s: Trying to copy non-optional chunk from file %s into optional chunk from file %s\n", bin_name, file_s, file_t);
		return -2;
	}
	if (!optional_t && optional_s) {
		fprintf(stderr, "%s: Trying to copy optional chunk from file %s into non-optional chunk from file %s\n", bin_name, file_s, file_t);
		return -2;
	}
	if (!optional_t && !optional_s && variable_types[chunk_t] != variable_types[chunk_s]) {
		fprintf(stderr, "%s: Trying to replace non-optional chunks of different types: %s, %s\n", bin_name, variable_types[chunk_t].c_str(), variable_types[chunk_s].c_str());
		return -2;
	}

	printf("\nGenerating file %s\n\n", out);

	unsigned rand_size = len_t + (end_s - start_s) - (end_t - start_t);
	assert(rand_size <= MAX_RAND_SIZE);
	memmove(rand_t + start_t + end_s + 1 - start_s, rand_t + end_t + 1, len_t - (end_t + 1));
	memcpy(rand_t + start_t, rand_s + start_s, end_s + 1 - start_s);

	get_chunk = false;
	smart_mutation = true;
	unsigned rand_end0 = rand_end = start_t + end_s - start_s;
	set_generator();

	unsigned char* file = NULL;
	unsigned file_size = afl_pre_save_handler(rand_t, MAX_RAND_SIZE, &file);
	if (!file || !file_size) {
		printf("Failed to generate mutated file!\n");
		return -2;
	}
	save_output(out);
	if (rand_end0 < rand_end)
		fprintf(stderr, "Warning: Consumed %u more decision bytes than expected while generating chunk.\n", rand_end - rand_end0);
	if (rand_end0 > rand_end)
		fprintf(stderr, "Warning: Consumed %u less decision bytes than expected while generating chunk.\n", rand_end0 - rand_end);
	fprintf(stderr, "%s: %s created\n", bin_name, out);

	delete[] rand_t;
	delete[] rand_s;
	return (rand_end > rand_end0) - (rand_end < rand_end0);
}





// smart_delete - apply a smart deletion
int smart_delete(int argc, char **argv)
{
	char *file_t = NULL;
	int start_t = -1;
	int end_t = -1;
	bool optional_t = false;

	bool success = false;

	unsigned char *rand_t = new unsigned char[MAX_RAND_SIZE];
	unsigned len_t;
	int rand_fd = open("/dev/urandom", O_RDONLY);
	ssize_t r = read(rand_fd, rand_t, MAX_RAND_SIZE);
	if (r != MAX_RAND_SIZE)
		printf("Read only %ld bytes from /dev/urandom\n", r);
	close(rand_fd);
	// Process options
	while (1)
	{
		static struct option long_options[] =
			{
				{"help", no_argument, 0, 'h'},
				{"targetfile", required_argument, 0, 1},
				{"targetstart", required_argument, 0, 2},
				{"targetend", required_argument, 0, 3},
				{0, 0, 0, 0}};
		int option_index = 0;
		int c = getopt_long(argc, argv, "",
							long_options, &option_index);

		// Detect the end of the options.
		if (c == -1)
			break;

		switch (c)
		{
		case 'h':
		case '?':
			fprintf(stderr, R"(delete: Smart Deletion
delete --targetfile file_t --targetstart start_t --targetend end_t OUTFILE

Apply a smart deletion operation, removing one chunk from file_t (byte range
[start_t, end_t]).  This can only be applied if the chunk is optional and the
following chunk is also optional.  A chunk is optional if there are calls to
FEof() and/or lookahead functions such as ReadBytes() right before the start
of the chunk.  This smart deletion should also fix constraints implemented in
the binary template (such as length fields).
)");
			return 0;

		case 1:
			file_t = optarg;
			break;
		case 2:
			start_t = strtol(optarg, NULL, 0);
			break;
		case 3:
			end_t = strtol(optarg, NULL, 0);
			break;
		}
	}
    
	if (optind >= argc) {
		fprintf(stderr, "%s: missing output file.\n", bin_name);
		return -2;
	}
	if (!file_t || start_t == -1 || end_t == -1) {
		fprintf(stderr, "%s: missing required arguments for target file.\n", bin_name);
		return -2;
	}

	// Main function
	char *out = argv[optind];


	printf("\nParsing file %s\n\n", file_t);
	success = false;
	is_delete = true;

	get_chunk = true;
	chunk_start = start_t;
	chunk_end = end_t;
	rand_start = rand_end = UINT_MAX;
	set_parser();
	setup_input(file_t);
	try
	{
		generate_file();
		success = true;
	}
	catch (int status)
	{
		delete_globals();
		if (status == 0)
			success = true;
	}
	catch (...)
	{
		delete_globals();
	}
	if (!success)
	{
		fprintf(stderr, "%s: Parsing %s failed\n", bin_name, file_t);
	}
	if (end_t != -1 && rand_start == UINT_MAX) {
		fprintf(stderr, "%s: Unable to find chunk in file %s\n", bin_name, file_t);
		return -2;
	}
	len_t = copy_rand(rand_t);
	start_t = rand_start;
	end_t = rand_end;
	optional_t = is_optional;

	if (!optional_t) {
		fprintf(stderr, "%s: The target chunk is not optional.\n", bin_name);
		return -2;
	}
	if (!following_is_optional) {
		fprintf(stderr, "%s: The target chunk is not followed by an optional chunk.\n", bin_name);
		return -2;
	}

	printf("\nGenerating file %s\n\n", out);

	memmove(rand_t + start_t, rand_t + end_t + 1, len_t - (end_t + 1));

	get_chunk = false;
	set_generator();

	unsigned char* file = NULL;
	unsigned file_size = afl_pre_save_handler(rand_t, MAX_RAND_SIZE, &file);
	if (!file || !file_size) {
		printf("Failed to generate mutated file!\n");
		return -2;
	}
	save_output(out);
	fprintf(stderr, "%s: %s created\n", bin_name, out);

	delete[] rand_t;
	return success ? 0 : -2;
}





// smart_insert - apply a smart insertion
int smart_insert(int argc, char **argv)
{
	char *file_t = NULL;
	int start_t = -1;
	char *file_s = NULL;
	int start_s = -1;
	int end_s = -1;
	bool optional_s = false;

	bool success = false;

	unsigned char *rand_t = new unsigned char[MAX_RAND_SIZE];
	unsigned char *rand_s = new unsigned char[MAX_RAND_SIZE];
	unsigned len_t;
	int rand_fd = open("/dev/urandom", O_RDONLY);
	ssize_t r = read(rand_fd, rand_t, MAX_RAND_SIZE);
	if (r != MAX_RAND_SIZE)
		printf("Read only %ld bytes from /dev/urandom\n", r);
	close(rand_fd);
	// Process options
	while (1)
	{
		static struct option long_options[] =
			{
				{"help", no_argument, 0, 'h'},
				{"targetfile", required_argument, 0, 1},
				{"targetstart", required_argument, 0, 2},
				{"sourcefile", required_argument, 0, 4},
				{"sourcestart", required_argument, 0, 5},
				{"sourceend", required_argument, 0, 6},
				{0, 0, 0, 0}};
		int option_index = 0;
		int c = getopt_long(argc, argv, "",
							long_options, &option_index);

		// Detect the end of the options.
		if (c == -1)
			break;

		switch (c)
		{
		case 'h':
		case '?':
			fprintf(stderr, R"(insert: Smart Insertion
insert --targetfile file_t --targetstart start_t
       --sourcefile file_s --sourcestart start_s --sourceend end_s OUTFILE

Apply a smart insertion operation, inserting one chunk from file_s (byte range
[start_s, end_s]) into file_t, with the first byte at start_t.  This can only
be applied if file_t originally had an optional chunk starting at start_t or
if start_t was the position right after the end of an appendable chunk.  A
chunk is optional if there are calls to FEof() and/or lookahead functions such
as ReadBytes() right before the start of the chunk.  A chunk is appendable if
there are calls to FEof() and/or lookahead functions such as ReadBytes() right
before the end of the chunk.  The source chunk from file_s must also be
optional.  This smart addition should also fix constraints implemented in the
binary template (such as length fields).  Command returns 0 if mutation worked
as expected or nonzero if it didn't work as expected.  This happens when the
chunk from file_s doesn't fit well in file_t because it required a larger or
smaller number of decision bytes in file_t than it did in file_s.
)");
			return 0;

		case 1:
			file_t = optarg;
			break;
		case 2:
			start_t = strtol(optarg, NULL, 0);
			break;
		case 4:
			file_s = optarg;
			break;
		case 5:
			start_s = strtol(optarg, NULL, 0);
			break;
		case 6:
			end_s = strtol(optarg, NULL, 0);
			break;
		}
	}
    
	if (optind >= argc) {
		fprintf(stderr, "%s: missing output file.\n", bin_name);
		return -2;
	}
	if (!file_t || start_t == -1) {
		fprintf(stderr, "%s: missing required arguments for target file.\n", bin_name);
		return -2;
	}
	if (!file_s || start_s == -1 || end_s == -1) {
		fprintf(stderr, "%s: missing required arguments for source file.\n", bin_name);
		return -2;
	}

	// Main function
	char *out = argv[optind];

	printf("Parsing file %s\n\n", file_s);
	success = false;

	get_chunk = true;
	chunk_start = start_s;
	chunk_end = end_s;
	rand_start = rand_end = UINT_MAX;
	set_parser();
	setup_input(file_s);
	try
	{
		generate_file();
		success = true;
	}
	catch (int status)
	{
		delete_globals();
		if (status == 0)
			success = true;
	}
	catch (...)
	{
		delete_globals();
	}
	if (!success)
	{
		fprintf(stderr, "%s: Parsing %s failed\n", bin_name, file_s);
		return -2;
	}
	if (rand_start == UINT_MAX) {
		fprintf(stderr, "%s: Unable to find chunk in file %s\n", bin_name, file_s);
		return -2;
	}
	copy_rand(rand_s);
	start_s = rand_start;
	end_s = rand_end;
	optional_s = is_optional;


	printf("\nParsing file %s\n\n", file_t);
	success = false;

	get_chunk = true;
	chunk_start = start_t;
	chunk_end = -1;
	rand_start = rand_end = UINT_MAX;
	set_parser();
	setup_input(file_t);
	try
	{
		generate_file();
		success = true;
	}
	catch (int status)
	{
		delete_globals();
		if (status == 0)
			success = true;
	}
	catch (...)
	{
		delete_globals();
	}
	if (!success)
	{
		fprintf(stderr, "%s: Parsing %s failed\n", bin_name, file_t);
		return -2;
	}
	len_t = copy_rand(rand_t);
	start_t = rand_start;

	if (rand_start == UINT_MAX) {
		fprintf(stderr, "%s: Invalid position for insertion into file %s.\n", bin_name, file_t);
		fprintf(stderr, "Insertion can only happen at the start of an optional chunk or after the end of an appendable chunk/file.\n");
		return -2;
	}
	if (!optional_s) {
		fprintf(stderr, "%s: Trying to insert non-optional chunk from file %s.\n", bin_name, file_s);
		return -2;
	}
	
	printf("\nGenerating file %s\n\n", out);

	unsigned rand_size = len_t + (end_s + 1 - start_s);
	assert(rand_size <= MAX_RAND_SIZE);
	memmove(rand_t + start_t + end_s + 1 - start_s, rand_t + start_t, len_t - start_t);
	memcpy(rand_t + start_t, rand_s + start_s, end_s + 1 - start_s);

	get_chunk = false;
	smart_mutation = true;
	is_optional = true;
	unsigned rand_end0 = rand_end = start_t + end_s - start_s;
	set_generator();

	unsigned char* file = NULL;
	unsigned file_size = afl_pre_save_handler(rand_t, MAX_RAND_SIZE, &file);
	if (!file || !file_size) {
		printf("Failed to generate mutated file!\n");
		return -2;
	}
	save_output(out);
	if (rand_end0 < rand_end)
		fprintf(stderr, "Warning: Consumed %u more decision bytes than expected while generating chunk.\n", rand_end - rand_end0);
	if (rand_end0 > rand_end)
		fprintf(stderr, "Warning: Consumed %u less decision bytes than expected while generating chunk.\n", rand_end0 - rand_end);
	fprintf(stderr, "%s: %s created\n", bin_name, out);

	delete[] rand_t;
	delete[] rand_s;
	return (rand_end > rand_end0) - (rand_end < rand_end0);
}



extern "C" void process_file(const char *file_name, const char *rand_name) {
	insertion_points.push_back({});
	deletable_chunks.push_back({});
	non_optional_index.push_back({});
	bool success = false;

	get_all_chunks = true;
	set_parser();
	setup_input(file_name);
	debug_print = false;
	try
	{
		generate_file();
		success = true;
	}
	catch (int status)
	{
		delete_globals();
		if (status == 0)
			success = true;
	}
	catch (...)
	{
		delete_globals();
	}
	get_all_chunks = false;
	save_output(rand_name);
	++file_index;
	optional_index.push_back(optional_chunks.size());
	if (!success && debug_print)
	{
		fprintf(stderr, "%s: Parsing %s failed\n", bin_name, file_name);
		return;
	}

}

unsigned read_rand_file(const char* file_name, unsigned char* rand_buffer) {
	int file_fd = open(file_name, O_RDONLY);
	if (file_fd == -1) {
		perror(file_name);
		exit(1);
	}
	ssize_t size = read(file_fd, rand_buffer, MAX_RAND_SIZE);
	if (size < 0) {
		perror("Failed to read seed file");
		exit(1);
	}
	close(file_fd);
	return size;
}

extern "C" int one_smart_mutation(int target_file_index, unsigned char** file, unsigned* file_size) {
	static unsigned char *rand_t = NULL;
	static unsigned char *rand_s = NULL;
	unsigned len_t = 0;
	if (!rand_t) {
		rand_t = new unsigned char[MAX_RAND_SIZE];
		rand_s = new unsigned char[MAX_RAND_SIZE];
		int rand_fd = open("/dev/urandom", O_RDONLY);
		ssize_t r = read(rand_fd, rand_t, MAX_RAND_SIZE);
		if (r != MAX_RAND_SIZE)
			printf("Read only %ld bytes from /dev/urandom\n", r);
		close(rand_fd);
	}

	bool old_debug_print = debug_print;
	switch (rand() % (deletable_chunks[target_file_index].size() ? 4 : 3)) {
	case 0:
	{
		NonOptional& no = non_optional_index[target_file_index][rand() % non_optional_index[target_file_index].size()];
		int chunk_index = no.start + rand() % no.size;
		Chunk& t = non_optional_chunks[no.type][chunk_index];
		Chunk& s = non_optional_chunks[no.type][rand() % non_optional_chunks[no.type].size()];
		if (debug_print)
			printf("Replacing: source non-optional chunk from file %d position %u %u %s %s\ninto target file %d non-optional chunk position %u %u %s %s\n", s.file_index, s.start, s.end, s.type, s.name, t.file_index, t.start, t.end, t.type, t.name);
		len_t = read_rand_file(rand_names[target_file_index].c_str(), rand_t);
		read_rand_file(rand_names[s.file_index].c_str(), rand_s);

		unsigned rand_size = len_t + (s.end - s.start) - (t.end - t.start);
		assert(rand_size <= MAX_RAND_SIZE);
		memmove(rand_t + t.start + s.end + 1 - s.start, rand_t + t.end + 1, len_t - (t.end + 1));
		memcpy(rand_t + t.start, rand_s + s.start, s.end + 1 - s.start);

		smart_mutation = true;
		get_parse_tree = true;
		rand_start = t.start;
		is_optional = false;
		chunk_name = t.name;
		unsigned rand_end0 = rand_end = t.start + s.end - s.start;
		set_generator();

		*file = NULL;
		debug_print = false;
		*file_size = afl_pre_save_handler(rand_t, MAX_RAND_SIZE, file);
		smart_mutation = false;
		get_parse_tree = false;
		debug_print = old_debug_print;
		if (!(*file) || !(*file_size)) {
			if (debug_print)
				printf("Failed to generate mutated file!\n");
			return -2;
		}
		if (debug_print && rand_end0 < rand_end)
			fprintf(stderr, "Warning: Consumed %u more decision bytes than expected while generating chunk.\n", rand_end - rand_end0);
		if (debug_print && rand_end0 > rand_end)
			fprintf(stderr, "Warning: Consumed %u less decision bytes than expected while generating chunk.\n", rand_end0 - rand_end);

		return (rand_end > rand_end0) - (rand_end < rand_end0);
	}
	case 1:
	{
		int chunk_index = optional_index[target_file_index] + rand() % (optional_index[target_file_index+1] - optional_index[target_file_index]);
		Chunk& t = optional_chunks[chunk_index];
		Chunk& s = optional_chunks[rand() % optional_chunks.size()];
		if (debug_print)
			printf("Replacing: source optional chunk from file %d position %u %u %s %s\ninto target file %d optional chunk position %u %u %s %s\n", s.file_index, s.start, s.end, s.type, s.name, t.file_index, t.start, t.end, t.type, t.name);
		len_t = read_rand_file(rand_names[target_file_index].c_str(), rand_t);
		read_rand_file(rand_names[s.file_index].c_str(), rand_s);

		unsigned rand_size = len_t + (s.end - s.start) - (t.end - t.start);
		assert(rand_size <= MAX_RAND_SIZE);
		memmove(rand_t + t.start + s.end + 1 - s.start, rand_t + t.end + 1, len_t - (t.end + 1));
		memcpy(rand_t + t.start, rand_s + s.start, s.end + 1 - s.start);

		smart_mutation = true;
		get_parse_tree = true;
		rand_start = t.start;
		is_optional = true;
		chunk_name = t.name;
		unsigned rand_end0 = rand_end = t.start + s.end - s.start;
		set_generator();

		*file = NULL;
		debug_print = false;
		*file_size = afl_pre_save_handler(rand_t, MAX_RAND_SIZE, file);
		smart_mutation = false;
		get_parse_tree = false;
		debug_print = old_debug_print;
		if (!(*file) || !(*file_size)) {
			if (debug_print)
				printf("Failed to generate mutated file!\n");
			return -2;
		}
		if (debug_print && rand_end0 < rand_end)
			fprintf(stderr, "Warning: Consumed %u more decision bytes than expected while generating chunk.\n", rand_end - rand_end0);
		if (debug_print && rand_end0 > rand_end)
			fprintf(stderr, "Warning: Consumed %u less decision bytes than expected while generating chunk.\n", rand_end0 - rand_end);

		return (rand_end > rand_end0) - (rand_end < rand_end0);
	}
	case 2:
	{
		InsertionPoint& ip = insertion_points[target_file_index][rand() % insertion_points[target_file_index].size()];
		Chunk& s = optional_chunks[rand() % optional_chunks.size()];
		if (debug_print)
			printf("Inserting: source chunk from file %d position %u %u %s %s\ninto target file %d position %u %s %s\n", s.file_index, s.start, s.end, s.type, s.name, target_file_index, ip.pos, ip.type, ip.name);
		len_t = read_rand_file(rand_names[target_file_index].c_str(), rand_t);
		read_rand_file(rand_names[s.file_index].c_str(), rand_s);

		unsigned rand_size = len_t + (s.end + 1 - s.start);
		assert(rand_size <= MAX_RAND_SIZE);
		memmove(rand_t + ip.pos + s.end + 1 - s.start, rand_t + ip.pos, len_t - ip.pos);
		memcpy(rand_t + ip.pos, rand_s + s.start, s.end + 1 - s.start);

		smart_mutation = true;
		get_parse_tree = true;
		rand_start = ip.pos;
		is_optional = true;
		chunk_name = s.name;
		unsigned rand_end0 = rand_end = ip.pos + s.end - s.start;
		set_generator();

		*file = NULL;
		debug_print = false;
		*file_size = afl_pre_save_handler(rand_t, MAX_RAND_SIZE, file);
		smart_mutation = false;
		get_parse_tree = false;
		debug_print = old_debug_print;
		if (!(*file) || !(*file_size)) {
			if (debug_print)
				printf("Failed to generate mutated file!\n");
			return -2;
		}
		if (debug_print && rand_end0 < rand_end)
			fprintf(stderr, "Warning: Consumed %u more decision bytes than expected while generating chunk.\n", rand_end - rand_end0);
		if (debug_print && rand_end0 > rand_end)
			fprintf(stderr, "Warning: Consumed %u less decision bytes than expected while generating chunk.\n", rand_end0 - rand_end);

		return (rand_end > rand_end0) - (rand_end < rand_end0);
	}
	case 3:
	{
		int index = rand() % deletable_chunks[target_file_index].size();
		Chunk& t = deletable_chunks[target_file_index][index];
		if (debug_print)
			printf("Deleting from file %d chunk %u %u %s %s\n", t.file_index, t.start, t.end, t.type, t.name);
		len_t = read_rand_file(rand_names[target_file_index].c_str(), rand_t);

		memmove(rand_t + t.start, rand_t + t.end + 1, len_t - (t.end + 1));

		deletable_chunks[target_file_index].erase(deletable_chunks[target_file_index].begin() + index);

		set_generator();

		*file = NULL;
		debug_print = false;
		*file_size = afl_pre_save_handler(rand_t, MAX_RAND_SIZE, file);
		debug_print = old_debug_print;
		if (!(*file) || !(*file_size)) {
			if (debug_print)
				printf("Failed to generate mutated file!\n");
			return -2;
		}

		return 0;
	}
	}
	return -2;
}

int mutations(int argc, char **argv)
{
	srand(time(NULL));
	for (int i = 1; i < argc; ++i) {
		char *file_name = argv[i];
		std::string rand_name = std::string(file_name) + "-decisions";
		rand_names.push_back(rand_name);
		process_file(file_name, rand_name.c_str());
	}
	unsigned char* file;
	unsigned size;
	debug_print = true;
	print_errors = true;
	for (int i = 0; i < 10000; ++i) {
		int result = one_smart_mutation(i % rand_names.size(), &file, &size);
		if (debug_print)
			printf("%d\n", result);
	}
	return 0;
}


int test(int argc, char *argv[])
{
	print_errors = true;
	int rand_fd = open("/dev/urandom", O_RDONLY);
	unsigned char *data = new unsigned char[MAX_RAND_SIZE];
	ssize_t r = read(rand_fd, data, MAX_RAND_SIZE);
	if (r != MAX_RAND_SIZE)
		printf("Read only %ld bytes from /dev/urandom\n", r);
	unsigned char *contents = new unsigned char[MAX_FILE_SIZE];
	unsigned char* file = NULL;
	size_t file_size;
	unsigned char* rand = NULL;
	size_t rand_size;
	size_t new_file_size = 0;
	int generated = 0;
	int i;
	int iterations = 10000;
	uint64_t start = get_cur_time_us();
	uint64_t parse_time = 0;
	for (i = 0; i < iterations; ++i)
	{
		ssize_t r = read(rand_fd, data, 4096);
		assert(r == 4096);
		file_size = afl_pre_save_handler(data, MAX_RAND_SIZE, &file);
		if (file_size && file) {
			generated += 1;
			uint64_t before = get_cur_time_us();
			bool parsed = afl_post_load_handler(file, file_size, &rand, &rand_size);
			uint64_t after = get_cur_time_us();
			parse_time += after - before;
			assert(file_size <= MAX_FILE_SIZE);
			memcpy(contents, file, file_size);
			memset(file, 0, file_size);
			file = NULL;
			if (!parsed) {
				printf("Failed to parse!\n");
				break;
			}
			new_file_size = afl_pre_save_handler(rand, rand_size, &file);
			if (!file || !file_size) {
				printf("Failed to re-generate!\n");
				break;
			}
			if (file_size != new_file_size || memcmp(contents, file, file_size)) {
				printf("Re-generated file different from original file!\n");
				break;
			}
		}
	}
	if (i != iterations) {
		write_file("r0", data, MAX_RAND_SIZE);
		write_file("f0", contents, file_size);
		write_file("r1", rand, rand_size);
		if (file)
			write_file("f1", file, new_file_size);
	}
	uint64_t end = get_cur_time_us();
	double time = (end - start) / 1.0e6;
	double ptime = parse_time / 1.0e6;
	printf("Tested %d files from %d attempts in %f s (parsing speed %f / s).\n", generated, i, time, generated / ptime);
	delete[] data;
	delete[] contents;
	return 0;
}

int benchmark(int argc, char *argv[])
{
	int rand_fd = open("/dev/urandom", O_RDONLY);
	unsigned char *data =  new unsigned char[MAX_RAND_SIZE];
	ssize_t r = read(rand_fd, data, MAX_RAND_SIZE);
	if (r != MAX_RAND_SIZE)
		printf("Read only %ld bytes from /dev/urandom\n", r);
	unsigned char* new_data = NULL;
	int generated = 0;
	int valid = 0;
	uint64_t total_bytes = 0;
	int i;
	int iterations = 10000;
	std::unordered_map<int,int> status;
	std::string fmt = std::string(bin_name, strchr(bin_name, '-') - bin_name);
	std::string output = "out." + fmt;
	std::string checker = "checkers/" + fmt + ".sh";
	uint64_t start = get_cur_time_us();
	for (i = 0; i < iterations; ++i)
	{
		ssize_t r = read(rand_fd, data, 4096);
		assert(r == 4096);
		size_t new_size = afl_pre_save_handler(data, MAX_RAND_SIZE, &new_data);
		if (new_size && new_data) {
			generated += 1;
			total_bytes += new_size;
			if (argc > 1) {
				save_output(output.c_str());
				int result = system(checker.c_str());
				if (WIFEXITED(result)) {
					++status[WEXITSTATUS(result)];
				}
				if (WIFSIGNALED(result)) {
					printf("killed by signal %d\n", WTERMSIG(result));
				}
				if (WIFEXITED(result) && WEXITSTATUS(result) == 0)
					++valid;
			}
		}
	}
	uint64_t end = get_cur_time_us();
	double time = (end - start) / 1.0e6;
	for (auto s : status)
		printf("status %d: %d\n", s.first, s.second);
	printf("Generated %d files from %d attempts in %f s.\n", generated, i, time);
	if (argc > 1)
		printf("Valid %d/%d = %f\n", valid, generated, (double)valid/(double)generated);
	if (generated)
		printf("Average file size %lu bytes.\n", total_bytes / generated);
	printf("Speed %f / s.\n", generated / time);
	delete[] data;
	return 0;
}

int version(int argc, char *argv[])
{
	fprintf(stderr, "This is %s\n", PACKAGE_STRING);
	return 0;
}


extern std::vector<std::vector<int>> found_paths;
unsigned currentPos = 0;

extern std::map<int, std::vector<int>> get_reachabilities();
extern std::map<int, std::vector<std::pair<int, int>>> get_paths();
extern std::list<int> get_terminals();
extern std::list<int> get_non_terminals();

std::list<std::vector<int>> get_kPaths(int k, std::map<int, std::vector<int>> reachabilities){
	//create list of k-paths from the reachability graph
	std::list<std::vector<int>> kPaths;
	auto terminals = get_terminals();
	auto keys = get_non_terminals();

	if(k == 1){
		terminals.merge(keys);
		for(auto it = terminals.begin(); it != terminals.end(); ++it){
			kPaths.merge(std::list<std::vector<int>> ({{*it}}));
		}
		kPaths.remove(std::vector<int> ({{-1}}));
		return kPaths;
	}
	// Iterate over all non-terminals
	for(auto iter = keys.begin(); iter != keys.end(); ++iter){
		std::list<std::vector<int>> key_starting_paths;
		std::vector<int> path({*iter});
		key_starting_paths.push_back(path);
		int j = 1;
		// For every non-terminal generate the reachable k-paths
		while(j < k){
			std::list<std::vector<int>> temp_list;
			for (auto it = key_starting_paths.begin(); it != key_starting_paths.end(); ++it){
				auto current = *it;
				auto toExpand = current.back();
				auto expansions = reachabilities[toExpand];
				for (auto i = expansions.begin(); i != expansions.end(); ++i){
					auto toAdd = current;
					if(std::find(terminals.begin(), terminals.end(), *i) == terminals.end() || j == k-1){
						toAdd.push_back(*i);
						if(std::find(temp_list.begin(), temp_list.end(), toAdd) == temp_list.end()){
							temp_list.push_back(toAdd);
						}
					}
				}
			}
			j++;
			key_starting_paths = temp_list;
		}
		kPaths.merge(key_starting_paths);
	}
	return kPaths;
}

std::vector<int> get_Path(std::map<int, std::vector<std::pair<int,int>>> paths, std::vector<int> path, int start_path, std::map<int, std::vector<int>> reach){
	auto start = reach[path[path.size()-1]];
	int shortest_way = -2;
	int shortest_no = INT_MAX;
	for(auto it = start.begin(); it != start.end(); ++it){
		auto options = paths[*it];
		for(auto option = options.begin(); option != options.end(); ++option){
			auto o = *option;
			if (start_path == o.second){
				if (o.first < shortest_no){
					shortest_way = *it;
					shortest_no = o.first;
				}
				break;
			}
		}
		if (shortest_no == 1){
			break;
		}
	}
	if (shortest_no > 0){
		path.emplace_back(shortest_way);
	}
	if(shortest_no > 1){
		path = get_Path(paths, path, start_path, reach);
	}
	return path;
}

unsigned int position;
int path_pos;
bool found_path;
std::vector<int> to_cover;
std::vector<int> chosen;
extern bool is_k_paths;
std::vector<int> k_path_stack;
unsigned int previous_gen_pos;
int tries = 0;
std::vector<std::vector<int>> k_paths;

int k_path_gen(int argc, char **argv){
	get_parse_tree = false;
	debug_print = false;
	print_errors = false;
	//make sure we have the right amount and type of arguments
	if (argc != 2){
		printf("Wrong number of arguments \n");
		return 1;
	}
	char *str = argv[1];
	char *pEnd;
	int k = strtol(str, &pEnd, 10);
	if (*pEnd != 0){
		printf("Wrong type of argument \n");
		return 1;
	}
	is_k_paths = true;


	//create a buffer that generates input containing the k-paths
	unsigned char * buffer;
	auto reachabilities = get_reachabilities();
	auto k_paths_list = get_kPaths(k, reachabilities);
	k_paths = std::vector<std::vector<int>>(k_paths_list.begin(), k_paths_list.end());
	//TODO: this doesn't actually shuffle ranodmly, every run results in the same shuffle.
	std::random_shuffle(k_paths.begin(), k_paths.end());
	auto k_paths_amount = k_paths.size();
	auto it = k_paths.begin();
	int generated_inputs = 0;
	while(it != k_paths.end()){
		// initialize variables to find the chosen k-path
		found_path = false;
		path_pos = 0;
		auto cur_path = *it;
		to_cover.clear();
		if(cur_path[0] != -1){
			to_cover.emplace_back(-1);
			auto paths = get_paths();
			to_cover = get_Path(paths, to_cover, cur_path[0], reachabilities);
			to_cover.insert(to_cover.end(), cur_path.begin(), cur_path.end());
		}
		else{
			to_cover = cur_path;
		}
		chosen = cur_path;

		int tries_per_path = 0;
		unsigned int result = 0;
		unsigned char * generated_input = NULL;
		while (tries_per_path < 5){
			// initialize randomness source
			buffer = new unsigned char [MAX_RAND_SIZE];
			int rand_fd = open("/dev/urandom", O_RDONLY);
			ssize_t r = read(rand_fd, buffer, MAX_RAND_SIZE);
			if (r != MAX_RAND_SIZE)
				printf("Read only %ld bytes from /dev/urandom\n", r);
			close(rand_fd);
			generated_input = NULL;

			// variables for iteration
			position = 0;
			result = 0;
			tries = 0;
			while(tries < 5){
				int last_non_zero = 0;
				int pos_val = 0;
				while(pos_val < 30){
					//Change the value of the current byte in the randomness source
					int temp;
					if (pos_val == 0)
						temp = 255;
					else
						temp = rand() % 256;
					buffer[position] = temp;
					previous_gen_pos = 1;
					k_path_stack = {-1};
					result = afl_pre_save_handler(buffer, MAX_RAND_SIZE, &generated_input);
					if (result != 0){
						last_non_zero = temp;
						if (found_path){
							break;
						}
					}
					//Reset found paths if we didn't find path we wanted
					found_paths.clear();
					//Avoid locking ourselves into a broken generation
					if (pos_val == 255 && result == 0){
						buffer[position] = last_non_zero;
					}
					pos_val++;
				}
				if (found_path){
					break;
				}
				position++;
				tries++;
			}
			if (found_path){
				break;
			}
			tries_per_path++;
		}
		//Generate the actual input here
		std::cout << "K path before size:" << k_paths.size() << "\n";
		if (found_paths.size() != 0) {
			for (auto it = found_paths.begin(); it != found_paths.end(); ++it){
				auto current = *it;
				k_paths.erase(std::remove(k_paths.begin(), k_paths.end(), *it), k_paths.end());
			}
			generated_inputs++;
			std::string f = "Input"+std::to_string(generated_inputs)+".txt";
			const char* file_name = f.c_str();
			write_file(file_name, generated_input, result);
			it = k_paths.begin();
		} else {
			// Might need to remove again
			++it;
		}
		std::cout << "Found path size:" << found_paths.size() << "\n";
		std::cout << "K path after size:" << k_paths.size() << "\n";
		found_paths.clear();
	}
	std::cout << "Amount of inputs generated: " << generated_inputs << ", Amount of k-paths covered: " << k_paths_amount-k_paths.size() << "/" << k_paths_amount << "\n";
	std::cout << "List of k-paths that we didn't find: \n";
	int e = 0;
	for (auto i = k_paths.begin(); i != k_paths.end(); ++i){
		auto k_path = *i;
		int t = 0;
		std::cout << "K-path " << e << ": ";
		for (auto it = k_path.begin(); it != k_path.end(); ++it){
			if(t == 0){
				std::cout << *it;
			}else{
				std::cout << " -> " << *it;
			}
			t++;
		}
		e++;
		std::cout << "\n\n";
	}
	return 0;
}

int test_k_paths(int argc, char **argv){
	if (argc != 2){
		printf("Wrong number of arguments \n");
		return 1;
	}
	char *str = argv[1];
	char *pEnd;
	int k = strtol(str, &pEnd, 10);
	if (*pEnd != 0){
		printf("Wrong type of argument \n");
		return 1;
	}
	auto k_paths = get_kPaths(k, get_reachabilities());
	for (auto it = k_paths.begin(); it != k_paths.end(); ++it){
		auto k_path = *it;
		printf("Start: ");
		for (auto i = k_path.begin(); i != k_path.end(); ++i){
			auto part = *i;
			std::cout << " -> (" << part << ")";
		}
		printf(" :, End\n");
	}
	return 0;
}

// Dispatch commands
typedef struct
{
	const char *name;
	int (*fun)(int argc, char **argv);
	const char *desc;
} COMMAND;

COMMAND commands[] = {
	{"fuzz", fuzz, "Generate random inputs"},
	{"parse", parse, "Parse inputs"},
	{"replace", smart_replace, "Apply a smart replacement"},
	{"delete", smart_delete, "Apply a smart deletion"},
	{"insert", smart_insert, "Apply a smart insertion"},
	{"mutations", mutations, "Smart mutations"},
	{"test", test, "Test if fuzzer is working properly (sanity checks)"},
	{"benchmark", benchmark, "Benchmark fuzzing"},
	{"version", version, "Show version"},
	{"test_k_paths", test_k_paths, "Test k-path generation"},
	{"k_path_gen", k_path_gen, "Generate files using the k-path algorithm for better grammar coverage"},
};

int help(int argc, char *argv[])
{
	version(argc, argv);
	fprintf(stderr, "%s: usage: %s COMMAND [OPTIONS...] [ARGS...]\n", bin_name, bin_name);
	fprintf(stderr, "Commands:\n");
	for (unsigned i = 0; i < sizeof(commands) / sizeof(COMMAND); i++)
		fprintf(stderr, "%-10s - %s\n", commands[i].name, commands[i].desc);
	fprintf(stderr, "Use COMMAND --help to learn more\n");
	return 0;
}

int main(int argc, char **argv)
{
	bin_name = get_bin_name(argv[0]);
	if (argc <= 1)
		return help(argc, argv);

	char *cmd = argv[1];
	for (unsigned i = 0; i < sizeof(commands) / sizeof(COMMAND); i++)
	{
		if (strcmp(cmd, commands[i].name) == 0)
			return (*commands[i].fun)(argc - 1, argv + 1);
	}

	// Invalid command
	help(argc, argv);
	return -1;
}
