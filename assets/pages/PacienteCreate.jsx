import React from 'react';
import {useState} from 'react';
import { Link } from 'react-router-dom';
import Layout from '../components/Layout'
import Swal from 'sweetalert2/dist/sweetalert2.js'
import axios from 'axios';

function PacienteCreate(){ //Esse componente diz respeito à página de cadastro de novos pacientes
    //declarando states
    const [id, setId] = useState('');
    const [nome, setNome] = useState('');
    const [cpf, setCpf] = useState('');
    const [sexo, setSexo] = useState('');
    const [endereco, setEndereco] = useState('');
    const [status, setStatus] = useState(true);
    const [dataNasc, setDataNasc] = useState('');
    const [isSaving, setIsSaving] = useState(false);

    const handleSave = async (event) => {
        event.preventDefault();
        setIsSaving(true);
        const formData = new FormData(event.currentTarget);
        try {
            await axios.post('/api/create', formData);
            await Swal.fire({icon: 'success', title: 'Dados salvos com sucesso', timer: 1000, showConfirmButton: false});
            document.getElementById('btn-home').click();
        } catch (error) {
            const data = error.response?.data;
            Swal.fire({icon: 'error', title: 'Não foi possível salvar',
                text: data?.error || Object.values(data?.errors || {}).join(' ') || 'Verifique a conexão e tente novamente.'});
        } finally {
            setIsSaving(false);
        }
    }

    return ( //com esse retorno, é renderizado todo o formulário de cadastro de um novo paciente
        <Layout>
            <div className="container">
                <h2 className="text-center mt-5 mb-3 text-light">Cadastro de um novo paciente</h2>
                <div className="card">
                    <div className="card-header">
                        <Link id='btn-home' className='btn btn-outline-info float-right' to={'/'}>Ver todos os pacientes</Link>
                    </div>
                    <div className="card-body">
                        <form onSubmit={handleSave}>
                            <div className="form-group">
                                <label htmlFor="nome">Nome:</label>
                                <input required type="text" maxLength={100} value={nome} className='form-control' id='nome' name='nome' onChange={(event)=>{setNome(event.target.value)}}/> {/* em todos os inputs, quando esses forem alterados, os states respectivos são setados com os valores inseridos pelo usuário */}
                                <label htmlFor="cpf">CPF:</label>
                                <input required type="text" maxLength={11} pattern="[0-9]{11}" value={cpf} className='form-control cpf' id='cpf' name='cpf' onChange={(event)=>{setCpf(event.target.value.replace(/[^0-9]/g, ''))}}/> {/* o replace é responsável por remover os "." e "-" caso o usuário digite dessa maneira */}
                                <label htmlFor="sexo">Sexo:</label>
                                <select required value={sexo} onChange={(event)=>{setSexo(document.getElementById("sexo").value)}} name="sexo" id="sexo" className="custom-select form-control">
                                    <option value="" disabled>Selecione seu sexo</option>
                                    <option value="Masculino">Masculino</option>
                                    <option value="Feminino">Feminino</option> 
                                    <option value="Outro">Outro</option>
                                </select>
                                <label htmlFor="dataNasc">Data de Nascimento:</label>
                                <input required type="date" min="1000-01-01" value={dataNasc} className='form-control data' id='dataNasc' name='dataNasc' onChange={(event)=>{setDataNasc(event.target.value)}}/>
                                <label htmlFor="endereco">Endereço:</label>
                                <input required type="text" maxLength={255} value={endereco || ''} className='form-control' id='endereco' name='endereco' onChange={(event)=>{setEndereco(event.target.value)}}/>
                            </div>
                            <button disabled={isSaving} type="submit" className='btn btn-outline-primary mt-3'> {/* os isSaving é responsável por habilitar ou desabilitar o botão quando necessário, além disso, quaando clicado (onClick) é chamado a função handleSave */}
                            Cadastrar
                            </button>
                        </form>
                    </div>
                </div>
            </div>
        </Layout>
    )
}

export default PacienteCreate; //exporta o componente PacienteCreate