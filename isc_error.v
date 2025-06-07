module firebird

fn get_error_message(error_number int) !string {
	if error_number in error_messages {
		message := error_messages[error_number]
		return '${message}\n'
	}
	return error('Unknown error: ${error_number}')
}
