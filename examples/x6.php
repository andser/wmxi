<?php

	include('_header.php');

	# http://wiki.webmoney.ru/wiki/show/Interfeys_X6
	$res = $wmxi->X6(
			ANOTHER_WMID,                                      # WM-идентификатор получателя сообщения
			'Тестовый заголовок',                              # тема сообщения
			"Текст многострочного\nсообщения <b>с тегами</b>"  # текст сообщения
	);

	print_r($res->toObject());

?>