package com.api;


import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@CrossOrigin
@RestController
public class FilmeController {

	@Autowired
    private FilmeRepository filmeRepository;

    public FilmeController(FilmeRepository filmeRepository) {
        this.filmeRepository = filmeRepository;
    }

    public FilmeController() {
    }

    @GetMapping("/filmes")
    public List<Filme> getFilmes() {
        return (List<Filme>) filmeRepository.findAll();
    }

    @PostMapping("/filmes/post")
    public Filme addUser(@RequestBody Filme filme) {
        return filmeRepository.save(filme);
    }

    @GetMapping("/filmes/{id}")
    public Optional<Filme> getFilme(@PathVariable Long id) {
        return filmeRepository.findById(id);
    }

    @DeleteMapping("/filmes/{id}")
    public void delete(@PathVariable Long id){
        filmeRepository.deleteById(id);
    }

    @PutMapping("/filmes")
    public void update(@RequestBody Filme filme){
        filmeRepository.save(filme);
    }

}